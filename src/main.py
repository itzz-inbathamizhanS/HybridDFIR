import sys
import os
import argparse
from pathlib import Path

# 1. Set the system path FIRST so Python knows where the root directory is
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# 2. THEN import your custom modules
from src.capture.live_ram import LiveRAMCapturer
from src.capture.native_ram import NativeLiveRAMAnalyzer
import questionary
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from src.intake import EvidenceIntake
from src.disk import ArtifactExtractor
from src.memory import ProcessScanner
from src.correlation import TimelineBuilder, ThreatScorer
from src.response import ReportGenerator

# ... (the rest of your code remains exactly the same below this)

console = Console()

def display_banner():
    """Displays a Claude-style rich banner header."""
    banner_text = Text("HYBRID MEMORY & DISK FORENSICS FRAMEWORK", style="bold cyan")
    sub_text = Text("Air-Gapped Local Forensic Analysis & Threat Correlation", style="dim white")
    combined = Text.assemble(banner_text, "\n", sub_text)
    
    console.print(
        Panel(
            combined,
            box=box.ROUNDED,
            border_style="bright_blue",
            padding=(1, 2),
            expand=False
        )
    )

def run_pipeline(image_path: str, image_type: str, mount_point: str = None):
    """Orchestrates the entire forensics analysis pipeline."""
    display_banner()

    # 1. Evidence Intake
    with console.status("[bold blue]Ingesting evidence & calculating hashes...", spinner="dots"):
        intake = EvidenceIntake(image_path, image_type)
        intake_metadata = intake.process_evidence()
    
    console.print("[bold green]✔ Evidence Intake Complete[/bold green]")
    
    # Metadata Table Display with Safe Dictionary Retrieval
    table = Table(title="Evidence Metadata", box=box.SIMPLE_HEAD, show_header=True, header_style="bold magenta")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")
    
    evidence_id = str(intake_metadata.get("evidence_id", "N/A"))
    table.add_row("Evidence ID", evidence_id)

    # Safely retrieve file size regardless of exact key naming
    file_size = intake_metadata.get("file_size_gb") or intake_metadata.get("file_size") or intake_metadata.get("size_gb") or 0.0
    table.add_row("File Size", f"{file_size} GB")

    sha256 = str(intake_metadata.get("sha256", "N/A"))
    table.add_row("SHA-256", sha256[:32] + "..." if len(sha256) > 32 else sha256)

    console.print(table)
    console.print()

    # 2. Memory & Disk Processing
    memory_processes = []
    disk_artifacts = []

    if image_type in ["memory", "hybrid"]:
        with console.status("[bold blue]Executing Volatility 3 plugins...", spinner="bouncingBar"):
            scanner = ProcessScanner(image_path)
            memory_processes = scanner.extract_running_processes()
        console.print(f"[bold green]✔ Memory Analysis:[/bold green] Extracted {len(memory_processes)} processes")

    if image_type in ["disk", "hybrid"] and mount_point:
        with console.status("[bold blue]Parsing Registry & Prefetch artifacts...", spinner="bouncingBar"):
            extractor = ArtifactExtractor(mount_point)
            disk_artifacts = extractor.extract_all_artifacts()
        console.print(f"[bold green]✔ Disk Analysis:[/bold green] Extracted {len(disk_artifacts)} artifacts")

    # 3. Threat Correlation & Timeline
    with console.status("[bold blue]Building timeline & scoring threat heuristics...", spinner="material"):
        timeline = TimelineBuilder.build_timeline(disk_artifacts, memory_processes)
        threats = ThreatScorer.evaluate_threats(memory_processes, disk_artifacts)
    
    console.print("[bold green]✔ Threat Correlation Complete[/bold green]\n")

    # 4. Generate Reports
    with console.status("[bold blue]Generating HTML Dashboard & JSON output...", spinner="dots"):
        report_gen = ReportGenerator(intake_metadata["evidence_id"])
        json_path = report_gen.generate_json_report(intake_metadata, timeline, threats)
        html_path = report_gen.generate_html_report(intake_metadata, timeline, threats)

    # Execution Summary Panel
    summary = Text()
    summary.append("Analysis Finished Successfully!\n\n", style="bold green")
    summary.append("JSON Report: ", style="bold white")
    summary.append(f"{json_path}\n", style="dim underline cyan")
    summary.append("HTML Report: ", style="bold white")
    summary.append(f"{html_path}", style="dim underline cyan")

    console.print(Panel(summary, title="Execution Summary", border_style="green", box=box.ROUNDED))

if __name__ == "__main__":
    if len(sys.argv) == 1:
        # NEW MENU: Ask what action the user wants to take
        action = questionary.select(
            "Select operation mode:",
            choices=[
                "1. Live Capture & Analyze (Capture current system RAM)",
                "2. Analyze Existing Evidence (Memory/Disk image)",
                "3. Native Live RAM Scan (Driverless, zero-binary)"
            ]
        ).ask()

        if not action:
            print("[!] Operation cancelled.")
            sys.exit(0)

        # Handle Live Capture
        if action.startswith("1"):
            capturer = LiveRAMCapturer()
            image_path = capturer.capture_memory()
            image_type = "memory"
            mount_point = None
            
            # Immediately pass the freshly captured RAM into your analysis pipeline
            run_pipeline(image_path, image_type, mount_point)

        # Handle Existing Evidence
        elif action.startswith("2"):
            image_path = questionary.path("Enter path to evidence image:").ask()
            if not image_path:
                sys.exit(0)

            image_type = questionary.select(
                "Select analysis type:",
                choices=["memory", "disk", "hybrid"]
            ).ask()

            mount_point = None
            if image_type in ["disk", "hybrid"]:
                mount_point = questionary.text("Enter mount point (e.g., D:\\):").ask()

            run_pipeline(image_path, image_type, mount_point)

        # Handle Native Live RAM Scan (zero-binary, no driver required)
        elif action.startswith("3"):
            analyzer = NativeLiveRAMAnalyzer(console=console)
            findings = analyzer.scan_live_ram()
            analyzer.display_findings(findings)

            # Convert to CorrelatedEvent format and save as standalone report
            correlated = analyzer.findings_to_correlated_events(findings)
            if correlated:
                import json, time
                from src.config.settings import OUTPUT_DIR
                report_path = OUTPUT_DIR / f"native_ram_scan_{int(time.time())}.json"
                with open(report_path, "w", encoding="utf-8") as fp:
                    json.dump({
                        "scan_type": "native_live_ram",
                        "total_findings": len(findings),
                        "correlated_events": correlated,
                        "raw_findings": findings,
                    }, fp, indent=2)
                console.print(
                    f"[bold green]✔ Report saved:[/bold green] {report_path}"
                )
            else:
                console.print("[green]No threats to report.[/green]")

    else:
        # Keep flag-based execution intact
        parser = argparse.ArgumentParser(description="Hybrid Forensics Framework")
        parser.add_argument("--image", required=True, help="Path to evidence image")
        parser.add_argument("--type", choices=["memory", "disk", "hybrid"], required=True)
        parser.add_argument("--mount", help="Mount point for disk analysis")
        args = parser.parse_args()

        run_pipeline(args.image, args.type, args.mount)