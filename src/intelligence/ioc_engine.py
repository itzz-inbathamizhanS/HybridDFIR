import json
import datetime
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from src.memory.process_tree import ProcessTreeBuilder
from src.network.connection_scanner import NetworkConnectionScanner

class IOCEngine:
    """
    Offline Indicator of Compromise (IOC) matcher.
    Ingests local STIX-like JSON indicators and matches them against live 
    memory, network, and artifact findings.
    """
    
    def __init__(self, ioc_file: str, console: Optional[Console] = None):
        self.ioc_file = ioc_file
        self.console = console or Console()
        self.iocs = self._load_iocs()
        
    def _load_iocs(self) -> Dict[str, set]:
        """Loads IOCs from the local JSON file into memory."""
        iocs = {
            "ips": set(),
            "domains": set(),
            "hashes": set(),
            "filenames": set()
        }
        
        try:
            with open(self.ioc_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            for indicator in data.get("indicators", []):
                type_ = indicator.get("type", "").lower()
                value = indicator.get("value", "").lower()
                
                if type_ == "ipv4-addr" or type_ == "ipv6-addr":
                    iocs["ips"].add(value)
                elif type_ == "domain-name":
                    iocs["domains"].add(value)
                elif type_ == "file:hashes":
                    iocs["hashes"].add(value)
                elif type_ == "file:name":
                    iocs["filenames"].add(value)
                    
            self.console.print(f"[bold green][+] Loaded {sum(len(v) for v in iocs.values())} indicators from {self.ioc_file}[/bold green]")
        except Exception as e:
            self.console.print(f"[bold red][FAIL] Failed to load IOCs: {e}[/bold red]")
            
        return iocs

    def scan_system(self) -> List[Dict[str, Any]]:
        """Scans live system state against the loaded IOCs."""
        self.console.print(Panel(
            f"[bold cyan]Offline IOC Engine[/bold cyan]\n"
            f"[dim]Cross-referencing live system telemetry against {self.ioc_file}[/dim]",
            border_style="cyan", box=box.ROUNDED, expand=False
        ))
        
        findings = []
        
        # 1. Check Processes against filename IOCs
        self.console.print("[blue]Scanning running processes...[/blue]")
        tree_builder = ProcessTreeBuilder(console=Console(quiet=True))
        processes = tree_builder.capture_snapshot()
        for p in processes:
            name = p["name"].lower()
            if name in self.iocs["filenames"]:
                findings.append({
                    "source": "Process Tree",
                    "threat_label": "IOC_PROCESS_NAME_MATCH",
                    "description": f"Running process matches known malicious IOC: {name} (PID: {p['pid']})",
                    "risk_score": 100,
                    "ioc_value": name,
                    "timestamp": datetime.datetime.now(datetime.UTC).isoformat() + "Z"
                })
                
        # 2. Check Network Connections against IP/Domain IOCs
        self.console.print("[blue]Scanning active network connections...[/blue]")
        net_scanner = NetworkConnectionScanner(console=Console(quiet=True))
        connections = net_scanner.scan_connections()
        for c in connections:
            remote_ip = c.get("remote_ip", "")
            if remote_ip and remote_ip in self.iocs["ips"]:
                findings.append({
                    "source": "Network",
                    "threat_label": "IOC_NETWORK_IP_MATCH",
                    "description": f"Process {c.get('process_name')} connected to malicious IP: {remote_ip}",
                    "risk_score": 100,
                    "ioc_value": remote_ip,
                    "timestamp": datetime.datetime.now(datetime.UTC).isoformat() + "Z"
                })
                
        self.render_results(findings)
        return findings

    def render_results(self, findings: List[Dict]):
        """Renders the IOC matches to the console."""
        self.console.print()
        
        if not findings:
            self.console.print("[bold green][+] No IOC matches found on the local system.[/bold green]")
            return
            
        table = Table(title="[bold red]CRITICAL: Indicator of Compromise Matches[/bold red]", box=box.DOUBLE_EDGE)
        table.add_column("Source", style="cyan")
        table.add_column("Threat Label", style="bold red")
        table.add_column("Matched Value", style="bright_yellow")
        table.add_column("Description", style="white")
        
        for f in findings:
            table.add_row(f["source"], f["threat_label"], f["ioc_value"], f["description"])
            
        self.console.print(table)
        self.console.print(f"[bold red][!] System is compromised. {len(findings)} IOC matches confirmed.[/bold red]")

if __name__ == "__main__":
    # Test script if executed directly
    engine = IOCEngine("indicators.json")
    engine.scan_system()
