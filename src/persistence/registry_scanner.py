"""
registry_scanner.py - Live Windows Registry Persistence Hunter
================================================================

Scans the LIVE Windows registry for persistence mechanisms that malware
uses to survive reboots.  Cross-references discovered entries against
the running process list to identify active implants vs dormant ones.

Capabilities
------------
* Scans 15+ standard autorun / persistence registry locations
* Enumerates scheduled tasks via ``schtasks``
* Detects LOLBin (Living Off the Land Binary) usage in persistence
* Cross-references with running processes for active implant detection
* MITRE ATT&CK TTP mapping for each persistence mechanism
* Structured output compatible with the correlation pipeline

Usage
-----
    from src.persistence.registry_scanner import PersistenceHunter

    hunter = PersistenceHunter()
    findings = hunter.scan_persistence()
    hunter.display_findings(findings)
"""

from __future__ import annotations

import datetime
import logging
import os
import subprocess
import winreg
from typing import List, Dict, Any, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
#  Known LOLBins - Living Off the Land Binaries
# ---------------------------------------------------------------------------
LOLBINS = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe",
    "installutil.exe", "wscript.exe", "cscript.exe", "schtasks.exe",
    "wmic.exe", "forfiles.exe", "pcalua.exe", "explorer.exe",
    "control.exe", "msconfig.exe", "msiexec.exe",
})

# Suspicious path fragments in persistence values
SUSPICIOUS_PATHS = frozenset({
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
    "\\downloads\\", "\\public\\", "\\programdata\\",
    "\\users\\default\\", "\\recycle",
})

# MITRE ATT&CK Mappings
_PERSISTENCE_MITRE = {
    "Run": "T1547.001",               # Registry Run Keys / Startup Folder
    "RunOnce": "T1547.001",
    "RunServices": "T1547.001",
    "Winlogon_Shell": "T1547.004",     # Winlogon Helper DLL
    "Winlogon_Userinit": "T1547.004",
    "Services": "T1543.003",           # Windows Service
    "ScheduledTask": "T1053.005",      # Scheduled Task
    "WMI_Subscription": "T1546.003",   # WMI Event Subscription
    "AppInit_DLLs": "T1546.010",       # AppInit DLLs
    "Image_File_Execution": "T1546.012",  # Image File Execution Options
    "Shell_Open": "T1546.001",         # Change Default File Association
}

# ---------------------------------------------------------------------------
#  Registry locations to scan
# ---------------------------------------------------------------------------
PERSISTENCE_LOCATIONS: List[Dict[str, Any]] = [
    # HKLM Run keys
    {"hive": winreg.HKEY_LOCAL_MACHINE,
     "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
     "category": "Run", "scope": "HKLM"},
    {"hive": winreg.HKEY_LOCAL_MACHINE,
     "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
     "category": "RunOnce", "scope": "HKLM"},
    # HKCU Run keys
    {"hive": winreg.HKEY_CURRENT_USER,
     "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
     "category": "Run", "scope": "HKCU"},
    {"hive": winreg.HKEY_CURRENT_USER,
     "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
     "category": "RunOnce", "scope": "HKCU"},
    # Winlogon
    {"hive": winreg.HKEY_LOCAL_MACHINE,
     "path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
     "category": "Winlogon_Shell", "scope": "HKLM",
     "values": ["Shell", "Userinit"]},
    # Services (enumerate subkeys)
    {"hive": winreg.HKEY_LOCAL_MACHINE,
     "path": r"SYSTEM\CurrentControlSet\Services",
     "category": "Services", "scope": "HKLM", "enumerate_subkeys": True},
    # AppInit_DLLs
    {"hive": winreg.HKEY_LOCAL_MACHINE,
     "path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
     "category": "AppInit_DLLs", "scope": "HKLM",
     "values": ["AppInit_DLLs"]},
    # Image File Execution Options (debugger persistence)
    {"hive": winreg.HKEY_LOCAL_MACHINE,
     "path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
     "category": "Image_File_Execution", "scope": "HKLM", "enumerate_subkeys": True},
    # Shell Open command
    {"hive": winreg.HKEY_LOCAL_MACHINE,
     "path": r"SOFTWARE\Classes\exefile\shell\open\command",
     "category": "Shell_Open", "scope": "HKLM"},
]


class PersistenceHunter:
    """
    Scans live Windows registry for persistence mechanisms and
    cross-references them with running processes.
    """

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()

    # ------------------------------------------------------------------
    #  Registry Scanning
    # ------------------------------------------------------------------

    def _read_registry_values(
        self, hive: int, path: str, specific_values: Optional[List[str]] = None
    ) -> List[Tuple[str, str, int]]:
        """Read all values (or specific ones) from a registry key."""
        results = []
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except (FileNotFoundError, PermissionError, OSError):
            return results

        try:
            if specific_values:
                for vname in specific_values:
                    try:
                        value, vtype = winreg.QueryValueEx(key, vname)
                        if value and str(value).strip():
                            results.append((vname, str(value), vtype))
                    except (FileNotFoundError, OSError):
                        pass
            else:
                idx = 0
                while True:
                    try:
                        name, value, vtype = winreg.EnumValue(key, idx)
                        if value and str(value).strip():
                            results.append((name, str(value), vtype))
                        idx += 1
                    except OSError:
                        break
        finally:
            winreg.CloseKey(key)

        return results

    def _enumerate_service_entries(self) -> List[Dict[str, Any]]:
        """Enumerate services and flag suspicious ones."""
        entries = []
        try:
            services_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services",
                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            )
        except (FileNotFoundError, PermissionError, OSError):
            return entries

        try:
            idx = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(services_key, idx)
                    idx += 1
                except OSError:
                    break

                try:
                    svc_key = winreg.OpenKey(
                        services_key, subkey_name, 0,
                        winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
                    )
                    try:
                        image_path, _ = winreg.QueryValueEx(svc_key, "ImagePath")
                        start_type, _ = winreg.QueryValueEx(svc_key, "Start")

                        # Only flag auto-start services (Start=2) with suspicious paths
                        if start_type in (0, 1, 2) and image_path:
                            image_lower = str(image_path).lower()
                            is_suspicious = any(
                                sp in image_lower for sp in SUSPICIOUS_PATHS
                            )
                            # Also flag services running from user directories
                            if "\\users\\" in image_lower and "\\appdata\\local\\microsoft" not in image_lower:
                                is_suspicious = True

                            if is_suspicious:
                                entries.append({
                                    "name": subkey_name,
                                    "value": str(image_path),
                                    "category": "Services",
                                    "scope": "HKLM",
                                    "start_type": start_type,
                                })
                    except (FileNotFoundError, OSError):
                        pass
                    finally:
                        winreg.CloseKey(svc_key)
                except (FileNotFoundError, PermissionError, OSError):
                    pass
        finally:
            winreg.CloseKey(services_key)

        return entries

    def _enumerate_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """Enumerate scheduled tasks using schtasks command."""
        entries = []
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if result.returncode != 0:
                return entries

            lines = result.stdout.strip().split("\n")
            if len(lines) < 2:
                return entries

            # Parse CSV - header is first line
            header = lines[0].strip('"').split('","')
            for line in lines[1:]:
                fields = line.strip('"').split('","')
                if len(fields) < len(header):
                    continue

                task_name = fields[0] if fields else ""
                # Find the "Task To Run" column
                action_idx = None
                for i, h in enumerate(header):
                    if "task to run" in h.lower():
                        action_idx = i
                        break

                if action_idx and action_idx < len(fields):
                    action = fields[action_idx]
                    action_lower = action.lower()

                    # Flag tasks with suspicious executables or paths
                    is_suspicious = False
                    for lolbin in LOLBINS:
                        if lolbin in action_lower:
                            is_suspicious = True
                            break
                    for sp in SUSPICIOUS_PATHS:
                        if sp in action_lower:
                            is_suspicious = True
                            break

                    if is_suspicious and task_name:
                        entries.append({
                            "name": task_name,
                            "value": action,
                            "category": "ScheduledTask",
                            "scope": "SYSTEM",
                        })

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            logger.debug("Scheduled task enumeration failed: %s", e)

        return entries

    # ------------------------------------------------------------------
    #  Threat Analysis
    # ------------------------------------------------------------------

    def _analyze_entry(
        self, entry: Dict[str, Any], running_processes: frozenset
    ) -> Dict[str, Any]:
        """Apply heuristics to a single persistence entry."""
        risk_score = 0
        threat_labels = []
        mitre_ttps = []
        value_lower = entry["value"].lower()
        category = entry["category"]

        # Base risk from persistence location
        if category in ("Run", "RunOnce"):
            risk_score += 30
        elif category in ("Winlogon_Shell", "Winlogon_Userinit"):
            risk_score += 50
        elif category == "Services":
            risk_score += 25
        elif category == "ScheduledTask":
            risk_score += 35
        elif category == "AppInit_DLLs":
            risk_score += 60
        elif category == "Image_File_Execution":
            risk_score += 70
        elif category == "Shell_Open":
            risk_score += 65

        # Add MITRE TTP
        ttp = _PERSISTENCE_MITRE.get(category)
        if ttp:
            mitre_ttps.append(ttp)

        # LOLBin detection
        for lolbin in LOLBINS:
            if lolbin in value_lower:
                threat_labels.append(f"LOLBIN_{lolbin.upper()}")
                risk_score += 25
                break

        # Suspicious path detection
        for sp in SUSPICIOUS_PATHS:
            if sp in value_lower:
                threat_labels.append("SUSPICIOUS_PATH")
                risk_score += 20
                break

        # Cross-reference with running processes
        # Extract executable name from the value
        exe_name = ""
        for part in value_lower.replace('"', '').split():
            if part.endswith(".exe"):
                exe_name = os.path.basename(part)
                break

        is_active = exe_name in running_processes if exe_name else False
        if exe_name and not is_active:
            threat_labels.append("DORMANT_IMPLANT")
            risk_score += 15
        elif is_active and risk_score > 30:
            threat_labels.append("ACTIVE_IMPLANT")
            risk_score += 20

        if not threat_labels:
            threat_labels.append("PERSISTENCE_ENTRY")

        return {
            "name": entry["name"],
            "value": entry["value"],
            "category": category,
            "scope": entry["scope"],
            "threat_labels": threat_labels,
            "risk_score": min(risk_score, 100),
            "is_active": is_active,
            "executable": exe_name,
            "mitre_ttps": list(dict.fromkeys(mitre_ttps)),
            "scan_timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
        }

    # ------------------------------------------------------------------
    #  Full Scan
    # ------------------------------------------------------------------

    def scan_persistence(
        self, running_process_names: Optional[frozenset] = None
    ) -> List[Dict[str, Any]]:
        """
        Scan all persistence locations and cross-reference with running processes.
        """
        self.console.print(
            Panel(
                "[bold cyan]Persistence Hunter[/bold cyan]\n"
                "[dim]Live registry autorun scanner with LOLBin detection[/dim]",
                border_style="bright_blue",
                box=box.ROUNDED,
                expand=False,
            )
        )

        # Build running process set if not provided
        if running_process_names is None:
            from src.capture.native_ram import NativeLiveRAMAnalyzer
            analyzer = NativeLiveRAMAnalyzer(console=Console(quiet=True))
            processes = analyzer.enumerate_processes()
            running_process_names = frozenset(name.lower() for _, name in processes)

        raw_entries: List[Dict[str, Any]] = []

        # Scan registry locations
        with self.console.status(
            "[bold blue]Scanning registry persistence locations...", spinner="dots"
        ):
            for loc in PERSISTENCE_LOCATIONS:
                if loc.get("enumerate_subkeys"):
                    continue  # Handled separately
                values = self._read_registry_values(
                    loc["hive"], loc["path"],
                    loc.get("values"),
                )
                for name, value, vtype in values:
                    raw_entries.append({
                        "name": name,
                        "value": value,
                        "category": loc["category"],
                        "scope": loc["scope"],
                    })

        self.console.print(
            f"[bold green][PASS][/bold green] Found [cyan]{len(raw_entries)}[/cyan] "
            f"registry persistence entries"
        )

        # Scan services
        with self.console.status(
            "[bold blue]Scanning Windows services...", spinner="dots"
        ):
            service_entries = self._enumerate_service_entries()
            raw_entries.extend(service_entries)

        self.console.print(
            f"[bold green][PASS][/bold green] Found [cyan]{len(service_entries)}[/cyan] "
            f"suspicious service entries"
        )

        # Scan scheduled tasks
        with self.console.status(
            "[bold blue]Scanning scheduled tasks...", spinner="dots"
        ):
            task_entries = self._enumerate_scheduled_tasks()
            raw_entries.extend(task_entries)

        self.console.print(
            f"[bold green][PASS][/bold green] Found [cyan]{len(task_entries)}[/cyan] "
            f"suspicious scheduled tasks"
        )

        # Analyze each entry
        findings = []
        for entry in raw_entries:
            analyzed = self._analyze_entry(entry, running_process_names)
            findings.append(analyzed)

        flagged = [f for f in findings if f["risk_score"] >= 40]
        self.console.print(
            f"[bold green][PASS][/bold green] Analysis complete - "
            f"[{'bold red' if flagged else 'green'}]"
            f"{len(flagged)} high-risk persistence mechanism(s)"
            f"[/{'bold red' if flagged else 'green'}]"
        )

        return findings

    # ------------------------------------------------------------------
    #  Display
    # ------------------------------------------------------------------

    def display_findings(
        self, findings: List[Dict[str, Any]], threats_only: bool = False
    ) -> None:
        """Render persistence findings as a rich console table."""
        if threats_only:
            displayable = [f for f in findings if f["risk_score"] >= 40]
        else:
            displayable = findings

        if not displayable:
            self.console.print(
                Panel(
                    "[bold green][PASS] No suspicious persistence mechanisms detected.[/bold green]",
                    border_style="green", box=box.ROUNDED, expand=False,
                )
            )
            return

        table = Table(
            title="[SECURITY] Persistence Mechanisms" + (" - Threats Only" if threats_only else ""),
            title_style="bold red" if threats_only else "bold cyan",
            box=box.SIMPLE, show_lines=False,
            header_style="bold magenta",
            row_styles=["", "dim"], expand=True,
        )
        table.add_column("Category", style="cyan", width=14)
        table.add_column("Scope", style="dim", width=6)
        table.add_column("Name", style="white", width=24)
        table.add_column("Value", style="bright_yellow", width=40, overflow="ellipsis")
        table.add_column("Status", width=10)
        table.add_column("Threat", width=22)
        table.add_column("Risk", justify="center", style="bold", width=6)

        for f in sorted(displayable, key=lambda x: x["risk_score"], reverse=True):
            risk = f["risk_score"]
            risk_style = (
                "bold red" if risk >= 70
                else ("yellow" if risk >= 40
                      else ("white" if risk > 0 else "dim green"))
            )
            status = Text("[CRITICAL] ACTIVE", style="bold red") if f["is_active"] else Text("[INFO] Dormant", style="dim")
            threat_text = ", ".join(f["threat_labels"])
            threat_style = "bold red" if risk >= 50 else ("white" if risk > 0 else "dim green")

            table.add_row(
                f["category"],
                f["scope"],
                f["name"],
                f["value"][:60] + ("..." if len(f["value"]) > 60 else ""),
                status,
                Text(threat_text, style=threat_style),
                Text(str(risk), style=risk_style),
            )

        self.console.print()
        self.console.print(table)
        self.console.print()

        # Summary
        high = sum(1 for f in findings if f["risk_score"] >= 70)
        med = sum(1 for f in findings if 40 <= f["risk_score"] < 70)
        low = sum(1 for f in findings if 0 < f["risk_score"] < 40)
        active = sum(1 for f in findings if f["is_active"])

        summary = Text()
        summary.append("Persistence Scan Summary\n\n", style="bold underline")
        summary.append(f"  [CRITICAL]  Critical / High  : {high}\n", style="bold red")
        summary.append(f"  [HIGH]  Medium           : {med}\n", style="yellow")
        summary.append(f"  [INFO]  Low              : {low}\n", style="dim white")
        summary.append(f"  [ALERT]  Active Implants  : {active}\n", style="bold red" if active else "dim green")
        summary.append(
            f"\n  Total entries: {len(findings)}  |  "
            f"High-risk: {high + med}",
            style="bold white",
        )

        self.console.print(
            Panel(summary, border_style="bright_blue" if high == 0 else "bright_red",
                  box=box.HEAVY, expand=False)
        )

    # ------------------------------------------------------------------
    #  Pipeline Output
    # ------------------------------------------------------------------

    def findings_to_correlated_events(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Convert persistence findings into CorrelatedEvent schema."""
        events = []
        for f in findings:
            if f["risk_score"] == 0:
                continue
            events.append({
                "timestamp": f["scan_timestamp_utc"],
                "source_module": "disk",  # persistence is registry/disk
                "event_type": "THREAT_DETECTED",
                "description": (
                    f"[Persistence] {', '.join(f['threat_labels'])} - "
                    f"{f['category']}/{f['scope']}: {f['name']} = {f['value'][:80]}"
                    f"{' [ACTIVE]' if f['is_active'] else ' [Dormant]'}"
                ),
                "risk_score": f["risk_score"],
                "mitre_attack_ttps": f.get("mitre_ttps", []),
            })
        return events
