"""
native_ram.py - Zero-Binary Driverless Live RAM & Process Memory Inspector
===========================================================================

Phase 1 of the Hybrid Memory & Disk Forensics Framework.

This module performs live process memory inspection on a running Windows system
using ONLY native Win32 APIs accessed through Python's ``ctypes`` module.
No third-party kernel drivers, no psutil - nothing that would trigger
driver-blocklist alerts on hardened endpoints.

Capabilities
------------
* Administrator privilege validation (``IsUserAnAdmin``)
* Full process enumeration via Toolhelp32 snapshot
  (``CreateToolhelp32Snapshot`` / ``Process32First`` / ``Process32Next``)
* Per-process virtual address space walking (``VirtualQueryEx``)
* Heuristic detection of suspicious memory regions:
    - MEM_COMMIT + PAGE_EXECUTE_READWRITE  (classic shellcode injection)
    - MEM_COMMIT + PAGE_EXECUTE_READ with no mapped file (hollowed section)
    - Unusually large (>1 MiB) private executable allocations
* Rich CLI output via ``rich`` tables and panels
* Structured dict/JSON output for downstream threat correlation

Usage
-----
    from src.capture.native_ram import NativeLiveRAMAnalyzer

    analyzer = NativeLiveRAMAnalyzer()
    findings = analyzer.scan_live_ram()       # list[dict]
    analyzer.display_findings(findings)       # rich console output

The returned ``findings`` list is directly consumable by
``src.correlation.ThreatScorer`` and ``src.response.ReportGenerator``.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import datetime
import logging
from typing import List, Dict, Any, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

# ---------------------------------------------------------------------------
#  Module-level logger
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
#  Win32 Constants
# ---------------------------------------------------------------------------

# --- Process access rights ---
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ           = 0x0010

# --- Memory state flags ---
MEM_COMMIT  = 0x00001000
MEM_RESERVE = 0x00002000
MEM_FREE    = 0x00010000

# --- Memory type flags ---
MEM_PRIVATE = 0x00020000
MEM_MAPPED  = 0x00040000
MEM_IMAGE   = 0x01000000

# --- Page protection flags ---
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_EXECUTE           = 0x10
PAGE_READWRITE         = 0x04
PAGE_NOACCESS          = 0x01
PAGE_GUARD             = 0x100

# --- Toolhelp32 ---
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value  # 0xFFFFFFFF... on 64-bit

# Heuristic thresholds
_LARGE_REGION_THRESHOLD = 1 * 1024 * 1024  # 1 MiB - private RX above this is unusual

# Human-readable lookup tables for console output
_PROTECTION_NAMES: Dict[int, str] = {
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
}

_MEM_TYPE_NAMES: Dict[int, str] = {
    MEM_PRIVATE: "MEM_PRIVATE",
    MEM_MAPPED:  "MEM_MAPPED",
    MEM_IMAGE:   "MEM_IMAGE",
}


def _protection_str(protect: int) -> str:
    """Return a human-readable name for a page protection constant."""
    base = protect & 0xFF  # strip modifier bits (GUARD, NOCACHE, ...)
    name = _PROTECTION_NAMES.get(base, f"0x{protect:04X}")
    if protect & PAGE_GUARD:
        name += "|GUARD"
    return name


def _mem_type_str(mem_type: int) -> str:
    return _MEM_TYPE_NAMES.get(mem_type, f"0x{mem_type:08X}")


# ---------------------------------------------------------------------------
#  Win32 Structure Definitions
# ---------------------------------------------------------------------------

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """Maps the Win32 MEMORY_BASIC_INFORMATION structure (64-bit safe)."""
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId",       wintypes.WORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wintypes.DWORD),
        ("Protect",           wintypes.DWORD),
        ("Type",              wintypes.DWORD),
    ]


class PROCESSENTRY32(ctypes.Structure):
    """Maps the Win32 PROCESSENTRY32W structure (wide-char variant)."""
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
#  NativeLiveRAMAnalyzer
# ---------------------------------------------------------------------------

class NativeLiveRAMAnalyzer:
    """
    Zero-binary, driverless live Windows process memory scanner.

    Uses only native Win32 APIs (kernel32 / shell32) via ``ctypes`` to
    enumerate processes, walk their virtual address space, and flag
    memory regions whose protection attributes are consistent with
    shellcode injection, process hollowing, or fileless malware
    persistence.
    """

    # Protections that are *always* suspicious for committed private regions
    SUSPICIOUS_PROTECTIONS = frozenset({
        PAGE_EXECUTE_READWRITE,   # 0x40 - classic shellcode
        PAGE_EXECUTE_WRITECOPY,   # 0x80 - rare, often malicious
    })

    # Protections that are *conditionally* suspicious
    # (e.g. RX on a large private allocation with no backing image)
    CONDITIONAL_PROTECTIONS = frozenset({
        PAGE_EXECUTE_READ,   # 0x20
        PAGE_EXECUTE,        # 0x10
    })

    # Known processes that legitimately allocate RWX memory for JIT compilation
    KNOWN_JIT_PROCESSES = frozenset({
        "chrome.exe", "brave.exe", "msedge.exe", "msedgewebview2.exe",
        "node.exe", "Code.exe", "Antigravity IDE.exe", "powershell.exe",
        "pwsh.exe", "Creative Cloud UI Helper.exe", "python.exe",
        "HPCommRecovery.exe", "HPSystemEventUtilityHost.exe",
        "DSAService.exe", "DSAUpdateService.exe",
        "ServiceShell.exe", "CrossDeviceService.exe",
    })

    # Prefixes for OEM processes that legitimately use RWX/.NET JIT memory
    KNOWN_JIT_PREFIXES = (
        "Dell.", "Intel", "Waves", "Lavasoft.", "DellOptimizer",
        "DellEnterprise", "HP", "Lenovo", "Asus", "Acer",
    )

    # Known security products that use copy-on-write executables
    KNOWN_AV_PROCESSES = frozenset({
        "QHActiveDefense.exe", "QHSafeTray.exe", "MsMpEng.exe",
    })

    # Prefixes for AV/security products
    KNOWN_AV_PREFIXES = (
        "Lavasoft.", "Malwarebytes", "Norton", "McAfee", "Kaspersky",
        "Avast", "AVG", "Bitdefender", "ESET", "Sophos",
    )

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()
        self._kernel32 = ctypes.windll.kernel32
        self._shell32  = ctypes.windll.shell32

    # ------------------------------------------------------------------
    #  1. Privilege & Environment Validation
    # ------------------------------------------------------------------

    def is_admin(self) -> bool:
        """
        Check whether the current process is running with elevated
        (Administrator) privileges using ``shell32.IsUserAnAdmin()``.
        """
        try:
            return bool(self._shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _require_admin(self) -> bool:
        """
        Guard method: prints a rich error panel and returns ``False``
        if the current session is not elevated.
        """
        if self.is_admin():
            return True

        self.console.print(
            Panel(
                "[bold red][FAIL]  Administrator privileges required[/bold red]\n\n"
                "Live RAM inspection needs an elevated process to open\n"
                "handles to protected system processes.\n\n"
                "[dim]Right-click your terminal -> 'Run as Administrator'[/dim]",
                title="Access Denied",
                border_style="red",
                box=box.HEAVY,
                expand=False,
            )
        )
        return False

    # ------------------------------------------------------------------
    #  2. Process Enumeration via Win32 Toolhelp32 Snapshot
    # ------------------------------------------------------------------

    def enumerate_processes(self) -> List[Tuple[int, str]]:
        """
        Enumerate all running processes using the Toolhelp32 snapshot API.

        Returns
        -------
        list of (pid, exe_name)
            Every process visible in the current snapshot, excluding
            PID 0 (System Idle Process).
        """
        processes: List[Tuple[int, str]] = []

        h_snap = self._kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if h_snap in (INVALID_HANDLE_VALUE, None, 0):
            logger.error("CreateToolhelp32Snapshot failed (returned INVALID_HANDLE_VALUE)")
            return processes

        try:
            pe = PROCESSENTRY32()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32)

            if not self._kernel32.Process32First(h_snap, ctypes.byref(pe)):
                logger.warning("Process32First returned FALSE - snapshot may be empty")
                return processes

            while True:
                pid = pe.th32ProcessID
                try:
                    name = pe.szExeFile.decode("utf-8", errors="replace").rstrip("\x00")
                except Exception:
                    name = "<unknown>"

                if pid != 0:  # skip System Idle Process
                    processes.append((pid, name))

                if not self._kernel32.Process32Next(h_snap, ctypes.byref(pe)):
                    break  # ERROR_NO_MORE_FILES - enumeration complete
        finally:
            self._kernel32.CloseHandle(h_snap)

        logger.info("Enumerated %d processes via Toolhelp32 snapshot", len(processes))
        return processes

    # ------------------------------------------------------------------
    #  3. Per-Process Memory Walk (VirtualQueryEx)
    # ------------------------------------------------------------------

    def _scan_process_memory(
        self,
        pid: int,
        process_name: str,
    ) -> List[Dict[str, Any]]:
        """
        Open *pid* and iterate through its virtual address space using
        ``VirtualQueryEx``.  Flag regions whose protection attributes
        match known injection heuristics.

        Parameters
        ----------
        pid : int
            Target process ID.
        process_name : str
            Executable name (for reporting only).

        Returns
        -------
        list of dict
            Each dict describes one suspicious memory region with keys:
            ``pid``, ``process_name``, ``base_address``, ``region_size``,
            ``protection``, ``protection_name``, ``mem_type``,
            ``mem_type_name``, ``threat_label``, ``risk_score``.
        """
        findings: List[Dict[str, Any]] = []

        # Attempt to open the target process
        h_process = self._kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False,
            pid,
        )
        if not h_process:
            # Access denied or process exited - silently skip
            return findings

        try:
            mbi = MEMORY_BASIC_INFORMATION()
            mbi_size = ctypes.sizeof(mbi)
            address: int = 0

            while True:
                bytes_returned = self._kernel32.VirtualQueryEx(
                    h_process,
                    ctypes.c_void_p(address),
                    ctypes.byref(mbi),
                    mbi_size,
                )
                if bytes_returned == 0:
                    break  # reached end of address space

                region_size: int = mbi.RegionSize or 0
                if region_size == 0:
                    break  # safety valve

                # Only examine committed pages
                if mbi.State == MEM_COMMIT:
                    protect = mbi.Protect
                    mem_type = mbi.Type
                    threat_label: Optional[str] = None
                    risk_score: int = 0

                    # --- Heuristic A: Always-suspicious protections ---
                    if protect in self.SUSPICIOUS_PROTECTIONS:
                        if protect == PAGE_EXECUTE_READWRITE:
                            is_jit = (
                                process_name in self.KNOWN_JIT_PROCESSES
                                or any(process_name.startswith(p) for p in self.KNOWN_JIT_PREFIXES)
                            )
                            if is_jit and mem_type == MEM_PRIVATE:
                                threat_label = "JIT_COMPILED_CODE"
                                risk_score = 10
                            else:
                                threat_label = "RWX_SHELLCODE_INJECTION"
                                risk_score = 90
                        elif protect == PAGE_EXECUTE_WRITECOPY:
                            is_av = (
                                process_name in self.KNOWN_AV_PROCESSES
                                or any(process_name.startswith(p) for p in self.KNOWN_AV_PREFIXES)
                            )
                            if is_av and mem_type == MEM_IMAGE:
                                threat_label = "AV_COPY_ON_WRITE"
                                risk_score = 10
                            else:
                                threat_label = "RWX_WRITECOPY_SUSPICIOUS"
                                risk_score = 80

                    # --- Heuristic B: Conditional - large private RX ---
                    elif (
                        protect in self.CONDITIONAL_PROTECTIONS
                        and mem_type == MEM_PRIVATE
                        and region_size >= _LARGE_REGION_THRESHOLD
                    ):
                        threat_label = "LARGE_PRIVATE_EXECUTABLE"
                        risk_score = 60

                    # --- Heuristic C: RWX with GUARD (staged payload) ---
                    elif (protect & PAGE_GUARD) and (protect & 0xFF) in (
                        PAGE_EXECUTE_READWRITE,
                        PAGE_EXECUTE_WRITECOPY,
                    ):
                        threat_label = "RWX_GUARD_STAGED_PAYLOAD"
                        risk_score = 75

                    if threat_label:
                        base_addr = mbi.BaseAddress or 0
                        findings.append({
                            "pid": pid,
                            "process_name": process_name,
                            "base_address": f"0x{base_addr:016X}",
                            "region_size": region_size,
                            "region_size_human": _human_size(region_size),
                            "protection": protect,
                            "protection_name": _protection_str(protect),
                            "mem_type": mem_type,
                            "mem_type_name": _mem_type_str(mem_type),
                            "threat_label": threat_label,
                            "risk_score": risk_score,
                            "scan_timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
                        })

                # Advance to the next region
                address += region_size

        except Exception as exc:
            logger.debug("Error scanning PID %d (%s): %s", pid, process_name, exc)
        finally:
            self._kernel32.CloseHandle(h_process)

        return findings

    # ------------------------------------------------------------------
    #  4. Full System Scan Orchestrator
    # ------------------------------------------------------------------

    def scan_live_ram(self) -> List[Dict[str, Any]]:
        """
        Top-level entry point: validate privileges, enumerate every
        process, walk each address space, and collect all suspicious
        memory regions into a single structured findings list.

        Returns
        -------
        list of dict
            Structured threat findings suitable for direct consumption
            by ``src.correlation.ThreatScorer`` and
            ``src.response.ReportGenerator``.  Returns an empty list if
            the session lacks administrator privileges.
        """
        if not self._require_admin():
            return []

        self.console.print(
            Panel(
                "[bold cyan]Native Live RAM Inspector[/bold cyan]\n"
                "[dim]Zero-binary driverless memory scan via Win32 API[/dim]",
                border_style="bright_blue",
                box=box.ROUNDED,
                expand=False,
            )
        )

        # ---- Enumerate processes ----
        with self.console.status(
            "[bold blue]Enumerating processes via Toolhelp32 snapshot...",
            spinner="dots",
        ):
            processes = self.enumerate_processes()

        self.console.print(
            f"[bold green][PASS][/bold green] Discovered [cyan]{len(processes)}[/cyan] "
            f"active processes"
        )

        # ---- Walk every address space ----
        all_findings: List[Dict[str, Any]] = []
        scanned = 0

        with self.console.status(
            "[bold blue]Scanning process memory regions for injection indicators...",
            spinner="bouncingBar",
        ):
            for pid, name in processes:
                hits = self._scan_process_memory(pid, name)
                if hits:
                    all_findings.extend(hits)
                else:
                    # Append a clean placeholder so every process is tracked in 'Show All' mode
                    all_findings.append({
                        "pid": pid,
                        "process_name": name,
                        "base_address": "-",
                        "region_size": 0,
                        "region_size_human": "-",
                        "protection": 0,
                        "protection_name": "-",
                        "mem_type": 0,
                        "mem_type_name": "-",
                        "threat_label": "CLEAN_PROCESS",
                        "risk_score": 0,
                        "scan_timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
                    })
                scanned += 1

        # Count distinct PIDs that flagged
        flagged_pids = len({f["pid"] for f in all_findings})

        self.console.print(
            f"[bold green][PASS][/bold green] Scanned [cyan]{scanned}[/cyan] processes - "
            f"[{'bold red' if flagged_pids else 'green'}]"
            f"{len(all_findings)} suspicious region(s) across {flagged_pids} process(es)"
            f"[/{'bold red' if flagged_pids else 'green'}]"
        )

        return all_findings

    # ------------------------------------------------------------------
    #  5. Rich CLI Display
    # ------------------------------------------------------------------

    def display_findings(self, findings: List[Dict[str, Any]], critical_only: bool = False) -> None:
        """
        Render a rich console table of suspicious memory findings.

        Parameters
        ----------
        findings : list of dict
            Output from :meth:`scan_live_ram`.
        critical_only : bool
            If True, only displays findings with a risk score >= 50.
        """
        if not findings:
            self.console.print(
                Panel(
                    "[bold green][PASS] No suspicious memory regions detected.[/bold green]\n"
                    "[dim]All scanned processes appear clean.[/dim]",
                    title="Scan Result",
                    border_style="green",
                    box=box.ROUNDED,
                    expand=False,
                )
            )
            return

        # Filter based on user request
        if critical_only:
            displayable_findings = [f for f in findings if f["risk_score"] >= 50]
        else:
            displayable_findings = findings

        if displayable_findings:
            table = Table(
                title="[WARN]  Suspicious Memory Regions Detected" if critical_only else "[INFO] All Scanned Processes & Memory Regions",
                title_style="bold red" if critical_only else "bold cyan",
                box=box.SIMPLE,
                show_lines=False,
                header_style="bold magenta",
                row_styles=["", "dim"],
                expand=True,
            )
            table.add_column("PID", style="cyan", justify="right", width=8)
            table.add_column("Process", style="white", width=22)
            table.add_column("Base Address", style="bright_yellow", width=20)
            table.add_column("Size", justify="right", style="white", width=12)
            table.add_column("Protection", style="bright_red", width=26)
            table.add_column("Type", style="dim", width=14)
            table.add_column("Threat", width=28)  # Removed default style to style per-row
            table.add_column("Risk", justify="center", style="bold", width=6)

            for f in sorted(displayable_findings, key=lambda x: x["risk_score"], reverse=True):
                risk = f["risk_score"]
                risk_style = "bold red" if risk >= 80 else ("yellow" if risk >= 60 else ("white" if risk > 0 else "dim green"))
                threat_style = "bold red" if risk >= 50 else ("white" if risk > 0 else "dim green")
                
                table.add_row(
                    str(f["pid"]),
                    f["process_name"],
                    f["base_address"],
                    f["region_size_human"],
                    f["protection_name"],
                    f["mem_type_name"],
                    Text(f["threat_label"], style=threat_style),
                    Text(str(risk), style=risk_style),
                )

            self.console.print()
            self.console.print(table)
            self.console.print()
        else:
            self.console.print("\n[bold green][PASS] No high-risk memory regions detected.[/bold green]\n")

        # Summary panel
        high = sum(1 for f in findings if f["risk_score"] >= 80)
        med  = sum(1 for f in findings if 60 <= f["risk_score"] < 80)
        low  = sum(1 for f in findings if 0 < f["risk_score"] < 60)
        clean = sum(1 for f in findings if f["risk_score"] == 0)

        summary = Text()
        summary.append("Scan Summary\n\n", style="bold underline")
        summary.append(f"  [CRITICAL]  Critical / High  : {high}\n", style="bold red")
        summary.append(f"  [HIGH]  Medium           : {med}\n", style="yellow")
        
        if critical_only:
            summary.append(f"  [INFO]  Low (JIT/AV)     : {low} (Suppressed from UI)\n", style="dim")
            summary.append(f"  [OK]  Clean Processes  : {clean} (Suppressed from UI)\n", style="dim green")
        else:
            summary.append(f"  [INFO]  Low (JIT/AV)     : {low}\n", style="dim white")
            summary.append(f"  [OK]  Clean Processes  : {clean}\n", style="dim green")
        summary.append(
            f"\n  Total flagged regions: {len(findings)}  |  "
            f"Unique PIDs: {len({f['pid'] for f in findings})}",
            style="bold white",
        )

        self.console.print(
            Panel(summary, border_style="bright_blue" if high == 0 else "bright_red", box=box.HEAVY, expand=False)
        )

    # ------------------------------------------------------------------
    #  6. Pipeline-Ready Structured Output
    # ------------------------------------------------------------------

    def findings_to_correlated_events(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Convert raw findings into the ``CorrelatedEvent`` schema defined
        in ``src/config/data_models.json`` so they can be fed directly
        into ``src.correlation.ThreatScorer`` and the reporting pipeline.

        Returns
        -------
        list of dict
            Each dict matches the ``CorrelatedEvent`` JSON schema::

                {
                    "timestamp": "2026-08-23T15:53:42Z",
                    "source_module": "memory",
                    "event_type": "THREAT_DETECTED",
                    "description": "...",
                    "risk_score": 90
                }
        """
        events: List[Dict[str, Any]] = []
        for f in findings:
            risk = min(f["risk_score"], 100)
            event_type = "THREAT_DETECTED" if risk >= 50 else "INFO_BENIGN_ALLOCATION"
            events.append({
                "timestamp": f.get("scan_timestamp_utc", datetime.datetime.utcnow().isoformat() + "Z"),
                "source_module": "memory",
                "event_type": event_type,
                "description": (
                    f"[NativeRAM] {f['threat_label']} in {f['process_name']} "
                    f"(PID {f['pid']}) at {f['base_address']}  "
                    f"Protection={f['protection_name']}  "
                    f"Size={f['region_size_human']}"
                ),
                "risk_score": risk,
            })
        return events


# ---------------------------------------------------------------------------
#  Utility helpers
# ---------------------------------------------------------------------------

def _human_size(nbytes: int) -> str:
    """Convert a byte count to a compact human-readable string."""
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(nbytes) < 1024.0:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024.0
    return f"{nbytes:.1f} TiB"


# ---------------------------------------------------------------------------
#  Standalone entry point - run the scanner directly for triage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    console = Console()

    analyzer = NativeLiveRAMAnalyzer(console=console)
    findings = analyzer.scan_live_ram()
    analyzer.display_findings(findings, critical_only=False)

    # Also emit correlated events for pipeline integration verification
    events = analyzer.findings_to_correlated_events(findings)
    if events:
        console.print(
            Panel(
                f"[bold cyan]{len(events)}[/bold cyan] CorrelatedEvent(s) ready "
                f"for threat correlation pipeline.",
                border_style="cyan",
                box=box.ROUNDED,
                expand=False,
            )
        )