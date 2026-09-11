
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from src.disk.artifact_extractor import ArtifactExtractor

class ArtifactAnalyzer:
    """
    Simulates deep parsing of Windows artifacts (Registry, Prefetch, EVTX).
    In a true production environment, this would use libregf or python-evtx.
    For this zero-dependency framework, we extract metadata using ArtifactExtractor
    and simulate heuristic anomaly detection on the artifact files themselves.
    """
    
    def __init__(self, mount_point: str, console: Optional[Console] = None):
        self.mount_point = mount_point
        self.console = console or Console()
        self.extractor = ArtifactExtractor(mount_point)
        
    def analyze_artifacts(self) -> List[Dict[str, Any]]:
        """Extracts and analyzes artifacts for threats."""
        self.console.print(Panel(
            f"[bold cyan]Windows Artifact Analyzer[/bold cyan]\n"
            f"[dim]Deep scanning Registry, Prefetch, and EVTX on mount: {self.mount_point}[/dim]",
            border_style="cyan", box=box.ROUNDED, expand=False
        ))
        
        with self.console.status("[bold blue]Extracting artifacts from disk...", spinner="dots"):
            raw_artifacts = self.extractor.extract_all_artifacts()
            
        findings = []
        
        # Simulate Analysis
        for art in raw_artifacts:
            art_type = art.get("artifact_type")
            path = art.get("source_path", "")
            
            # Simulated Heuristic: Suspicious Prefetch
            if art_type == "Prefetch File":
                exe_name = art.get("details", {}).get("executable_identified", "").lower()
                if exe_name in ["mimikatz.exe", "psexec.exe", "netcat.exe", "nc.exe"]:
                    findings.append({
                        "artifact_type": "Prefetch",
                        "source_path": path,
                        "threat_label": "MALICIOUS_TOOL_EXECUTED",
                        "description": f"Prefetch indicates execution of known malicious tool: {exe_name}",
                        "risk_score": 95,
                        "timestamp": art.get("timestamp")
                    })
                    
            # Simulated Heuristic: Cleared Event Logs
            elif art_type == "Event Log":
                log_name = art.get("details", {}).get("log_name", "")
                size = art.get("details", {}).get("size_bytes", 0)
                # If Security.evtx is extremely small, it might have been cleared
                if log_name.lower() == "security.evtx" and size < 65536: # Less than 64KB
                    findings.append({
                        "artifact_type": "Event Log",
                        "source_path": path,
                        "threat_label": "EVENT_LOG_CLEARED",
                        "description": "Security.evtx is suspiciously small, indicating potential log clearing (T1070.001)",
                        "risk_score": 85,
                        "timestamp": art.get("timestamp")
                    })
                    
            # Simulated Heuristic: Suspicious NTUSER.DAT location
            elif art_type == "Registry Hive":
                hive_type = art.get("details", {}).get("hive_type", "")
                if hive_type == "NTUSER.DAT":
                    username = art.get("details", {}).get("username", "")
                    if username.lower() in ["defaultapppool", "networkservice"]:
                        findings.append({
                            "artifact_type": "Registry",
                            "source_path": path,
                            "threat_label": "SUSPICIOUS_SERVICE_HIVE",
                            "description": f"Interactive NTUSER.DAT found for service account: {username}",
                            "risk_score": 75,
                            "timestamp": art.get("timestamp")
                        })
                        
        self.render_results(raw_artifacts, findings)
        return findings

    def render_results(self, raw_artifacts: List[Dict], findings: List[Dict]):
        """Renders the analysis results to the console."""
        
        # Stats
        stats = {}
        for art in raw_artifacts:
            typ = art["artifact_type"]
            stats[typ] = stats.get(typ, 0) + 1
            
        self.console.print(f"[bold green][+][/bold green] Extracted and analyzed [cyan]{len(raw_artifacts)}[/cyan] artifacts.")
        for k, v in stats.items():
            self.console.print(f"  - {k}: {v}")
            
        self.console.print()
        
        if not findings:
            self.console.print("[bold green][+] No artifact anomalies detected.[/bold green]")
            return
            
        table = Table(title="[bold red]Artifact Anomalies Detected[/bold red]", box=box.SIMPLE_HEAD)
        table.add_column("Type", style="cyan")
        table.add_column("Threat Label", style="bold red")
        table.add_column("Risk", justify="center", style="bold yellow")
        table.add_column("Description", style="white")
        
        for f in findings:
            table.add_row(f["artifact_type"], f["threat_label"], str(f["risk_score"]), f["description"])
            
        self.console.print(table)
