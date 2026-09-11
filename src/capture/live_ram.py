"""
live_ram.py - Live RAM Capture Engine (Native-First + Optional Driver)
======================================================================

Primary mode is **native capture** (zero-binary, driverless):

1.  Runs the NativeLiveRAMAnalyzer to enumerate all process memory
    regions and detect suspicious allocations.
2.  Uses ``MiniDumpWriteDump`` from ``dbghelp.dll`` to create forensic
    process dumps for every suspicious process found by the scan.
3.  Bundles everything (scan JSON + per-process dumps) into a single
    timestamped output directory.

If the user passes ``--driver`` flag, it *first* attempts a full
physical RAM dump via winpmem.  This is disabled by default to avoid
triggering Windows Security popups on hardened endpoints.

All Win32 calls go through Python ``ctypes`` - no third-party
drivers, no psutil.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import time
from typing import Optional, List, Dict, Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box

# ---------------------------------------------------------------------------
#  Win32 constants for MiniDumpWriteDump
# ---------------------------------------------------------------------------
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ           = 0x0010
MiniDumpWithFullMemory    = 0x00000002

console = Console()


class LiveRAMCapturer:
    """
    Forensic live memory capture with native Win32 APIs.

    ``/capture`` is the **deep forensic acquisition** command:
    - Scans all process memory for injection indicators
    - Creates full process MiniDumps for every suspicious PID
    - Saves structured JSON report + raw dump files
    - Produces a forensic evidence package ready for offline analysis

    Compare with ``/scan`` which is a lightweight read-only inspection.
    """

    def __init__(self, output_dir: str = "output", use_driver: bool = False) -> None:
        self.output_dir = output_dir
        self.use_driver = use_driver
        os.makedirs(self.output_dir, exist_ok=True)

        self.timestamp = int(time.time())
        self.dump_path = os.path.join(
            self.output_dir, f"live_capture_{self.timestamp}.raw"
        )
        self.winpmem_path = os.path.join(os.getcwd(), "winpmem.exe")

    # ------------------------------------------------------------------
    #  Privilege check
    # ------------------------------------------------------------------

    def is_admin(self) -> bool:
        """Check if the script is running with administrative privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    # ------------------------------------------------------------------
    #  Public entry point
    # ------------------------------------------------------------------

    def capture_memory(self) -> Optional[str]:
        """
        Perform a forensic memory capture.

        Returns
        -------
        str or None
            Path to the capture artefact (raw image or native capture
            directory).  ``None`` only if admin privileges are missing.
        """
        if not self.is_admin():
            console.print(
                Panel(
                    "[bold red][FAIL]  Administrator privileges required[/bold red]\n\n"
                    "Live RAM capture needs an elevated process.\n"
                    "[dim]Right-click your terminal -> 'Run as Administrator'[/dim]",
                    title="Access Denied",
                    border_style="red",
                    box=box.HEAVY,
                    expand=False,
                )
            )
            return None

        # --- Optional: try winpmem if explicitly requested ---
        if self.use_driver:
            result = self._try_winpmem()
            if result:
                return result
            console.print(
                "\n[bold yellow][*] Driver blocked - switching to "
                "Native Capture Mode...[/bold yellow]\n"
            )

        # --- Primary: native forensic capture ---
        return self._native_forensic_capture()

    # ------------------------------------------------------------------
    #  Strategy 1 - winpmem (only when --driver flag is set)
    # ------------------------------------------------------------------

    def _try_winpmem(self) -> Optional[str]:
        """Try winpmem.exe.  Returns dump path on success, None on failure."""
        if not os.path.exists(self.winpmem_path):
            console.print(
                "[dim]winpmem.exe not found - skipping driver-based capture.[/dim]"
            )
            return None

        console.print(
            f"[bold blue]Loading kernel driver and capturing live RAM "
            f"to {self.dump_path}...[/bold blue]"
        )
        try:
            subprocess.run(
                [self.winpmem_path, "-o", self.dump_path], check=True
            )
            console.print(
                "[bold green][PASS] Live Memory Snapshot Completed Successfully.[/bold green]"
            )
            return self.dump_path

        except subprocess.CalledProcessError as exc:
            console.print(
                f"\n[bold red][FAIL] winpmem driver blocked "
                f"(exit code {exc.returncode})[/bold red]"
            )
            return None

    # ------------------------------------------------------------------
    #  Strategy 2 - native forensic capture (default)
    # ------------------------------------------------------------------

    def _native_forensic_capture(self) -> Optional[str]:
        """
        Full forensic capture using only native Win32 APIs:
        1. Scan all process memory (same engine as /scan)
        2. Create MiniDumps of suspicious processes
        3. Package everything into a forensic evidence directory
        """
        from src.capture.native_ram import NativeLiveRAMAnalyzer

        # Create a dedicated output directory for this capture session
        capture_dir = os.path.join(
            self.output_dir, f"native_capture_{self.timestamp}"
        )
        dumps_dir = os.path.join(capture_dir, "process_dumps")
        os.makedirs(capture_dir, exist_ok=True)
        os.makedirs(dumps_dir, exist_ok=True)

        # --- Banner ---
        console.print(
            Panel(
                "[bold cyan]Forensic Memory Capture[/bold cyan]\n"
                "[dim]Native Win32 API - no kernel driver required[/dim]\n\n"
                "[white]Phase 1:[/white] Scan all process memory regions\n"
                "[white]Phase 2:[/white] Create MiniDumps of suspicious processes\n"
                "[white]Phase 3:[/white] Package forensic evidence",
                border_style="bright_blue",
                box=box.DOUBLE,
                expand=False,
            )
        )

        # --- Phase 1: Scan ---
        console.print("\n[bold white]--- Phase 1: Memory Scan ---[/bold white]\n")
        analyzer = NativeLiveRAMAnalyzer(console=console)
        findings = analyzer.scan_live_ram()

        # Only show a compact summary, NOT the full table (that's what /scan is for)
        high = sum(1 for f in findings if f["risk_score"] >= 80)
        med  = sum(1 for f in findings if 50 <= f["risk_score"] < 80)
        low  = sum(1 for f in findings if f["risk_score"] < 50)
        
        scan_summary = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        scan_summary.add_column("Label", style="white")
        scan_summary.add_column("Count", style="bold", justify="right")
        scan_summary.add_row("[CRITICAL] Critical/High risk regions", f"[bold red]{high}[/bold red]")
        scan_summary.add_row("[HIGH] Medium risk regions", f"[yellow]{med}[/yellow]")
        scan_summary.add_row("[INFO] Low/Benign (JIT, AV)", f"[dim]{low}[/dim]")
        scan_summary.add_row("[STATS] Total flagged regions", f"[bold]{len(findings)}[/bold]")
        scan_summary.add_row("[INFO] Unique processes flagged", f"[bold]{len({f['pid'] for f in findings})}[/bold]")
        console.print(scan_summary)

        # Save the structured findings report
        correlated = analyzer.findings_to_correlated_events(findings)
        report = {
            "capture_mode": "native_forensic",
            "capture_timestamp": self.timestamp,
            "scan_type": "native_live_ram",
            "total_findings": len(findings),
            "high_risk_findings": high,
            "medium_risk_findings": med,
            "low_risk_findings": low,
            "correlated_events": correlated,
            "raw_findings": findings,
        }
        report_path = os.path.join(capture_dir, "scan_results.json")
        with open(report_path, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2)

        # --- Phase 2: MiniDumps ---
        suspicious_pids: Dict[int, str] = {
            f["pid"]: f["process_name"]
            for f in findings
            if f["risk_score"] >= 50
        }

        console.print(f"\n[bold white]--- Phase 2: Process Memory Dumps ---[/bold white]\n")

        if suspicious_pids:
            console.print(
                f"[bold blue]Acquiring memory dumps for "
                f"{len(suspicious_pids)} suspicious process(es)...[/bold blue]\n"
            )

            success_count = 0
            fail_count = 0
            dump_manifest: List[Dict[str, Any]] = []

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=30),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console,
            ) as progress:
                task = progress.add_task(
                    "Dumping process memory...", total=len(suspicious_pids)
                )
                for pid, pname in suspicious_pids.items():
                    dump_file = os.path.join(dumps_dir, f"{pname}_pid{pid}.dmp")
                    progress.update(task, description=f"PID {pid} ({pname})")

                    ok = self._create_minidump(pid, dump_file)
                    if ok:
                        success_count += 1
                        file_size = os.path.getsize(dump_file)
                        dump_manifest.append({
                            "pid": pid,
                            "process_name": pname,
                            "dump_path": dump_file,
                            "dump_size_bytes": file_size,
                            "status": "SUCCESS",
                        })
                    else:
                        fail_count += 1
                        dump_manifest.append({
                            "pid": pid,
                            "process_name": pname,
                            "dump_path": dump_file,
                            "status": "ACCESS_DENIED",
                        })
                        # Clean up empty file if created
                        if os.path.exists(dump_file):
                            try:
                                os.remove(dump_file)
                            except OSError:
                                pass

                    progress.advance(task)

            # Show dump results table
            dump_table = Table(
                title="Process Dump Results",
                title_style="bold cyan",
                box=box.SIMPLE_HEAD,
                show_lines=False,
                header_style="bold magenta",
                expand=False,
            )
            dump_table.add_column("PID", style="cyan", justify="right", width=8)
            dump_table.add_column("Process", style="white", width=30)
            dump_table.add_column("Status", width=14)
            dump_table.add_column("Dump Size", justify="right", style="dim", width=12)

            for entry in dump_manifest:
                if entry["status"] == "SUCCESS":
                    status_text = Text("[PASS] Captured", style="bold green")
                    size_text = _human_size(entry["dump_size_bytes"])
                else:
                    status_text = Text("[DENIED] Denied", style="dim")
                    size_text = "-"

                dump_table.add_row(
                    str(entry["pid"]),
                    entry["process_name"],
                    status_text,
                    size_text,
                )

            console.print(dump_table)

            # Save dump manifest
            manifest_path = os.path.join(capture_dir, "dump_manifest.json")
            with open(manifest_path, "w", encoding="utf-8") as fp:
                json.dump(dump_manifest, fp, indent=2)

            console.print(
                f"\n[bold green][PASS] Captured {success_count}/"
                f"{len(suspicious_pids)} process dumps[/bold green]"
            )
            if fail_count:
                console.print(
                    f"[dim]  {fail_count} process(es) denied access "
                    f"(protected system processes)[/dim]"
                )
        else:
            console.print(
                "[green]No high-risk processes found - "
                "skipping dump creation.[/green]"
            )

        # --- Phase 3: Package evidence ---
        console.print(f"\n[bold white]--- Phase 3: Evidence Package ---[/bold white]\n")

        # Calculate total capture size
        total_size = 0
        for root, dirs, files in os.walk(capture_dir):
            for f in files:
                total_size += os.path.getsize(os.path.join(root, f))

        summary = Text()
        summary.append("Forensic Capture Complete\n\n", style="bold green")
        summary.append("  [DIR]  Output directory : ", style="white")
        summary.append(f"{capture_dir}\n", style="underline cyan")
        summary.append("  [REPORT]  Scan report      : ", style="white")
        summary.append(f"scan_results.json\n", style="dim cyan")
        if suspicious_pids:
            summary.append("  [CAPTURE]  Process dumps    : ", style="white")
            summary.append(f"process_dumps/  ({success_count} files)\n", style="dim cyan")
            summary.append("  [FILE]  Dump manifest    : ", style="white")
            summary.append(f"dump_manifest.json\n", style="dim cyan")
        summary.append("  [PACKAGE]  Total size       : ", style="white")
        summary.append(f"{_human_size(total_size)}\n", style="bold white")
        summary.append("\n  [dim]Use /scan for a quick read-only inspection.[/dim]", style="dim")

        console.print(
            Panel(
                summary,
                title="[bold]Capture Summary[/bold]",
                border_style="bright_green",
                box=box.DOUBLE,
                expand=False,
            )
        )

        return capture_dir

    # ------------------------------------------------------------------
    #  MiniDumpWriteDump via ctypes
    # ------------------------------------------------------------------

    def _create_minidump(self, pid: int, dump_path: str) -> bool:
        """
        Create a minidump for a single process using
        ``dbghelp!MiniDumpWriteDump``.

        Returns ``True`` on success, ``False`` on access-denied or error.
        """
        kernel32 = ctypes.windll.kernel32
        dbghelp  = ctypes.windll.dbghelp

        # Open the target process
        h_process = kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
        )
        if not h_process:
            return False

        try:
            # Create the output file
            h_file = kernel32.CreateFileW(
                dump_path,
                0x40000000,   # GENERIC_WRITE
                0,            # no sharing
                None,
                2,            # CREATE_ALWAYS
                0x80,         # FILE_ATTRIBUTE_NORMAL
                None,
            )
            if h_file == ctypes.c_void_p(-1).value:
                return False

            try:
                success = dbghelp.MiniDumpWriteDump(
                    h_process,
                    pid,
                    h_file,
                    MiniDumpWithFullMemory,
                    None,
                    None,
                    None,
                )
                return bool(success)
            finally:
                kernel32.CloseHandle(h_file)
        finally:
            kernel32.CloseHandle(h_process)


# ---------------------------------------------------------------------------
#  Utility
# ---------------------------------------------------------------------------

def _human_size(nbytes: int) -> str:
    """Convert a byte count to a compact human-readable string."""
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(nbytes) < 1024.0:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024.0
    return f"{nbytes:.1f} TiB"