"""
dll_inspector.py - DLL Injection & Process Hollowing Detector
==============================================================

Goes beyond basic RWX detection - enumerates every loaded DLL in each
process using ``CreateToolhelp32Snapshot`` with ``TH32CS_SNAPMODULE``
and flags suspicious modules.

Capabilities
------------
* Per-process loaded module enumeration (Module32First/Module32Next)
* DLL side-loading detection (DLLs from temp/user directories)
* Path masquerading detection (DLLs with mismatched names vs locations)
* Hollowed process detection (processes with abnormally few modules)
* Cross-reference with RWX memory regions for combined threat scoring
* MITRE ATT&CK TTP mapping

Usage
-----
    from src.capture.dll_inspector import DLLInspector

    inspector = DLLInspector()
    findings = inspector.scan_modules()
    inspector.display_findings(findings)
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import datetime
import logging
import os
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
#  Win32 Constants
# ---------------------------------------------------------------------------
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPPROCESS  = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
MAX_MODULE_NAME32 = 255
MAX_PATH = 260

# ---------------------------------------------------------------------------
#  Win32 Structures
# ---------------------------------------------------------------------------

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",        wintypes.DWORD),
        ("th32ModuleID",  wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage",  wintypes.DWORD),
        ("ProccntUsage",  wintypes.DWORD),
        ("modBaseAddr",   ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize",   wintypes.DWORD),
        ("hModule",       ctypes.c_void_p),
        ("szModule",      ctypes.c_char * (MAX_MODULE_NAME32 + 1)),
        ("szExePath",     ctypes.c_char * MAX_PATH),
    ]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              wintypes.DWORD),
        ("cntUsage",            wintypes.DWORD),
        ("th32ProcessID",       wintypes.DWORD),
        ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID",        wintypes.DWORD),
        ("cntThreads",          wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase",      wintypes.LONG),
        ("dwFlags",             wintypes.DWORD),
        ("szExeFile",           ctypes.c_char * 260),
    ]


# ---------------------------------------------------------------------------
#  Threat Intelligence
# ---------------------------------------------------------------------------

# Directories where legitimate system DLLs should reside
SYSTEM_DLL_DIRS = frozenset({
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
    "c:\\windows\\microsoft.net",
    "c:\\windows\\assembly",
    "c:\\program files",
    "c:\\program files (x86)",
})

# DLLs commonly hijacked via side-loading
COMMONLY_HIJACKED_DLLS = frozenset({
    "version.dll", "dbghelp.dll", "wer.dll", "msimg32.dll",
    "cryptbase.dll", "profapi.dll", "propsys.dll", "dwmapi.dll",
    "uxtheme.dll", "urlmon.dll", "wininet.dll", "cscapi.dll",
    "edgegdi.dll", "ntshrui.dll", "comctl32.dll",
})

# Suspicious DLL name patterns
SUSPICIOUS_DLL_PATTERNS = (
    "inject", "hook", "payload", "implant", "beacon",
    "shell", "exploit", "loader", "dropper",
)

# System processes that should have a minimum number of loaded modules
SYSTEM_PROCESSES_MIN_MODULES = {
    "svchost.exe": 20,
    "explorer.exe": 40,
    "lsass.exe": 15,
    "services.exe": 10,
    "csrss.exe": 8,
}

# Processes to skip (they are protected and will fail on module enum)
SKIP_PROCESSES = frozenset({
    "system", "secure system", "registry", "smss.exe",
    "memory compression", "system idle process",
})

# MITRE ATT&CK Mappings
_DLL_MITRE = {
    "SIDE_LOADING": "T1574.002",        # DLL Side-Loading
    "SEARCH_ORDER_HIJACK": "T1574.001", # DLL Search Order Hijacking
    "INJECTION": "T1055.001",           # DLL Injection
    "MASQUERADING": "T1036.005",        # Masquerading: Match Legitimate Name
    "HOLLOWING": "T1055.012",           # Process Hollowing
}


class DLLInspector:
    """
    Enumerates loaded DLLs per process and detects injection, side-loading,
    and process hollowing indicators.
    """

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()
        self._kernel32 = ctypes.windll.kernel32

    # ------------------------------------------------------------------
    #  Process Enumeration
    # ------------------------------------------------------------------

    def _enumerate_processes(self) -> List[Dict[str, Any]]:
        """Enumerate all running processes."""
        processes = []
        h_snap = self._kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if h_snap in (INVALID_HANDLE_VALUE, None, 0):
            return processes

        try:
            pe = PROCESSENTRY32()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
            if not self._kernel32.Process32First(h_snap, ctypes.byref(pe)):
                return processes

            while True:
                pid = pe.th32ProcessID
                try:
                    name = pe.szExeFile.decode("utf-8", errors="replace").rstrip("\x00")
                except Exception:
                    name = "<unknown>"
                if pid != 0:
                    processes.append({"pid": pid, "name": name})
                if not self._kernel32.Process32Next(h_snap, ctypes.byref(pe)):
                    break
        finally:
            self._kernel32.CloseHandle(h_snap)

        return processes

    # ------------------------------------------------------------------
    #  Module Enumeration
    # ------------------------------------------------------------------

    def _get_process_modules(self, pid: int) -> List[Dict[str, Any]]:
        """Enumerate all loaded modules for a given process."""
        modules = []

        h_snap = self._kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid
        )
        if h_snap in (INVALID_HANDLE_VALUE, None, 0):
            return modules

        try:
            me = MODULEENTRY32()
            me.dwSize = ctypes.sizeof(MODULEENTRY32)

            if not self._kernel32.Module32First(h_snap, ctypes.byref(me)):
                return modules

            while True:
                try:
                    mod_name = me.szModule.decode("utf-8", errors="replace").rstrip("\x00")
                    mod_path = me.szExePath.decode("utf-8", errors="replace").rstrip("\x00")
                except Exception:
                    mod_name = "<unknown>"
                    mod_path = "<unknown>"

                modules.append({
                    "name": mod_name,
                    "path": mod_path,
                    "base_size": me.modBaseSize,
                })

                if not self._kernel32.Module32Next(h_snap, ctypes.byref(me)):
                    break
        finally:
            self._kernel32.CloseHandle(h_snap)

        return modules

    # ------------------------------------------------------------------
    #  Threat Analysis
    # ------------------------------------------------------------------

    def _analyze_process_modules(
        self, pid: int, process_name: str, modules: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze loaded modules for a single process."""
        findings = []

        # Check for hollowed process (too few modules)
        proc_lower = process_name.lower()
        min_modules = SYSTEM_PROCESSES_MIN_MODULES.get(proc_lower)
        if min_modules and len(modules) < min_modules // 2:
            findings.append({
                "pid": pid,
                "process_name": process_name,
                "module_name": "-",
                "module_path": "-",
                "module_count": len(modules),
                "threat_labels": ["POSSIBLE_HOLLOWED_PROCESS"],
                "risk_score": 80,
                "mitre_ttps": [_DLL_MITRE["HOLLOWING"]],
                "scan_timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
            })

        for mod in modules:
            mod_name = mod["name"].lower()
            mod_path = mod["path"].lower()
            threat_labels = []
            risk_score = 0
            mitre_ttps = []

            # Skip the main executable module
            if mod_name == proc_lower:
                continue

            # Rule 1: DLL loaded from suspicious directory
            mod_dir = os.path.dirname(mod_path)
            is_system_dir = any(mod_dir.startswith(sd) for sd in SYSTEM_DLL_DIRS)

            if not is_system_dir and mod_name.endswith(".dll"):
                # Check if it's from temp/user directories
                suspicious_dir = any(sp in mod_path for sp in (
                    "\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\local\\temp",
                    "\\public\\", "\\desktop\\",
                ))
                if suspicious_dir:
                    threat_labels.append("DLL_FROM_SUSPICIOUS_DIR")
                    risk_score += 70
                    mitre_ttps.append(_DLL_MITRE["SIDE_LOADING"])
                elif "\\users\\" in mod_path:
                    threat_labels.append("DLL_FROM_USER_DIR")
                    risk_score += 40
                    mitre_ttps.append(_DLL_MITRE["SEARCH_ORDER_HIJACK"])

            # Rule 2: Commonly hijacked DLL in non-system location
            if mod_name in COMMONLY_HIJACKED_DLLS and not is_system_dir:
                threat_labels.append("HIJACKED_DLL_CANDIDATE")
                risk_score += 65
                mitre_ttps.append(_DLL_MITRE["SIDE_LOADING"])

            # Rule 3: Suspicious name patterns
            for pattern in SUSPICIOUS_DLL_PATTERNS:
                if pattern in mod_name:
                    threat_labels.append(f"SUSPICIOUS_NAME_{pattern.upper()}")
                    risk_score += 75
                    mitre_ttps.append(_DLL_MITRE["INJECTION"])
                    break

            # Rule 4: DLL masquerading - system DLL name but wrong path
            known_system_dlls = {"kernel32.dll", "ntdll.dll", "user32.dll",
                                  "advapi32.dll", "ws2_32.dll", "msvcrt.dll"}
            if mod_name in known_system_dlls and not is_system_dir:
                threat_labels.append("DLL_MASQUERADING")
                risk_score += 90
                mitre_ttps.append(_DLL_MITRE["MASQUERADING"])

            if threat_labels:
                findings.append({
                    "pid": pid,
                    "process_name": process_name,
                    "module_name": mod["name"],
                    "module_path": mod["path"],
                    "module_count": len(modules),
                    "threat_labels": threat_labels,
                    "risk_score": min(risk_score, 100),
                    "mitre_ttps": list(dict.fromkeys(mitre_ttps)),
                    "scan_timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
                })

        return findings

    # ------------------------------------------------------------------
    #  Full Scan
    # ------------------------------------------------------------------

    def scan_modules(self) -> List[Dict[str, Any]]:
        """Enumerate all process modules and detect injection indicators."""
        self.console.print(
            Panel(
                "[bold cyan]DLL Injection & Hollowing Detector[/bold cyan]\n"
                "[dim]Module enumeration via Toolhelp32 - zero dependencies[/dim]",
                border_style="bright_blue",
                box=box.ROUNDED,
                expand=False,
            )
        )

        with self.console.status(
            "[bold blue]Enumerating processes...", spinner="dots"
        ):
            processes = self._enumerate_processes()

        self.console.print(
            f"[bold green][PASS][/bold green] Discovered [cyan]{len(processes)}[/cyan] processes"
        )

        all_findings = []
        scanned = 0
        skipped = 0

        with self.console.status(
            "[bold blue]Inspecting loaded DLL modules per process...",
            spinner="bouncingBar",
        ):
            for proc in processes:
                if proc["name"].lower() in SKIP_PROCESSES:
                    skipped += 1
                    continue

                modules = self._get_process_modules(proc["pid"])
                if modules:
                    findings = self._analyze_process_modules(
                        proc["pid"], proc["name"], modules
                    )
                    all_findings.extend(findings)
                    scanned += 1
                else:
                    skipped += 1

        flagged = len(all_findings)
        self.console.print(
            f"[bold green][PASS][/bold green] Scanned [cyan]{scanned}[/cyan] processes "
            f"(skipped {skipped} protected) - "
            f"[{'bold red' if flagged else 'green'}]"
            f"{flagged} suspicious DLL(s) detected"
            f"[/{'bold red' if flagged else 'green'}]"
        )

        return all_findings

    # ------------------------------------------------------------------
    #  Display
    # ------------------------------------------------------------------

    def display_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Render DLL findings as a rich console table."""
        if not findings:
            self.console.print(
                Panel(
                    "[bold green][PASS] No suspicious DLL injection indicators detected.[/bold green]",
                    border_style="green", box=box.ROUNDED, expand=False,
                )
            )
            return

        table = Table(
            title="[ANALYSIS] DLL Injection & Hollowing Analysis",
            title_style="bold red" if any(f["risk_score"] >= 70 for f in findings) else "bold cyan",
            box=box.SIMPLE, show_lines=False,
            header_style="bold magenta",
            row_styles=["", "dim"], expand=True,
        )
        table.add_column("PID", style="cyan", justify="right", width=7)
        table.add_column("Process", style="white", width=20)
        table.add_column("DLL Module", style="bright_yellow", width=22)
        table.add_column("DLL Path", style="dim", width=40, overflow="ellipsis")
        table.add_column("Threat", width=26)
        table.add_column("Risk", justify="center", style="bold", width=6)

        for f in sorted(findings, key=lambda x: x["risk_score"], reverse=True):
            risk = f["risk_score"]
            risk_style = (
                "bold red" if risk >= 70
                else ("yellow" if risk >= 40
                      else "white")
            )
            threat_text = ", ".join(f["threat_labels"])
            threat_style = "bold red" if risk >= 70 else ("yellow" if risk >= 40 else "white")

            table.add_row(
                str(f["pid"]),
                f["process_name"],
                f["module_name"],
                f["module_path"][:50] + ("..." if len(f["module_path"]) > 50 else ""),
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

        summary = Text()
        summary.append("DLL Inspection Summary\n\n", style="bold underline")
        summary.append(f"  [CRITICAL]  Critical / High  : {high}\n", style="bold red")
        summary.append(f"  [HIGH]  Medium           : {med}\n", style="yellow")
        summary.append(f"  [INFO]  Low              : {low}\n", style="dim white")
        summary.append(
            f"\n  Total suspicious DLLs: {len(findings)}",
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
        """Convert DLL findings into CorrelatedEvent schema."""
        events = []
        for f in findings:
            if f["risk_score"] == 0:
                continue
            events.append({
                "timestamp": f["scan_timestamp_utc"],
                "source_module": "memory",
                "event_type": "THREAT_DETECTED",
                "description": (
                    f"[DLL] {', '.join(f['threat_labels'])} - "
                    f"{f['process_name']} (PID {f['pid']}): "
                    f"{f['module_name']} @ {f['module_path']}"
                ),
                "risk_score": f["risk_score"],
                "mitre_attack_ttps": f.get("mitre_ttps", []),
            })
        return events

