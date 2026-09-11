import ctypes
import ctypes.wintypes as wintypes
from typing import List, Dict, Any, Optional, Tuple
from rich.console import Console
from rich.tree import Tree
from rich.text import Text
from rich.panel import Panel
from rich import box
import datetime

# --- Toolhelp32 Constants ---
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

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

class ProcessTreeBuilder:
    """
    Builds a hierarchical process tree using native Win32 APIs and 
    flags anomalous parent-child relationships.
    """
    
    # Heuristics for suspicious relationships
    SUSPICIOUS_PARENTS = {
        "smss.exe": ["system"],  # smss should only be spawned by System
        "csrss.exe": ["smss.exe"],
        "wininit.exe": ["smss.exe"],
        "winlogon.exe": ["smss.exe"],
        "services.exe": ["wininit.exe"],
        "lsass.exe": ["wininit.exe"],
        "svchost.exe": ["services.exe"],
        "taskhostw.exe": ["svchost.exe", "services.exe"],
    }
    
    # Processes that should never spawn a shell
    NO_SHELL_PARENTS = {"lsass.exe", "smss.exe", "csrss.exe", "winlogon.exe", "wininit.exe", "spoolsv.exe"}
    SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "wsl.exe"}

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self._kernel32 = ctypes.windll.kernel32
        
    def capture_snapshot(self) -> List[Dict[str, Any]]:
        """Captures a snapshot of all running processes."""
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
                ppid = pe.th32ParentProcessID
                try:
                    name = pe.szExeFile.decode("utf-8", errors="replace").rstrip("\x00")
                except Exception:
                    name = "<unknown>"
                    
                if pid != 0:
                    processes.append({
                        "pid": pid,
                        "ppid": ppid,
                        "name": name.lower()
                    })
                
                if not self._kernel32.Process32Next(h_snap, ctypes.byref(pe)):
                    break
        finally:
            self._kernel32.CloseHandle(h_snap)
            
        return processes

    def analyze_tree(self) -> Tuple[List[Dict], Dict[int, List[Dict]], List[Dict]]:
        """Builds the tree and identifies anomalies."""
        processes = self.capture_snapshot()
        
        # Build lookup maps
        proc_map = {p["pid"]: p for p in processes}
        children_map = {p["pid"]: [] for p in processes}
        
        # Roots of the tree (processes where PPID doesn't exist in our snapshot)
        roots = []
        
        findings = []
        
        for p in processes:
            pid = p["pid"]
            ppid = p["ppid"]
            name = p["name"]
            
            if ppid in children_map:
                children_map[ppid].append(p)
            else:
                roots.append(p)
                
            # --- Heuristic Checks ---
            parent_name = proc_map.get(ppid, {}).get("name", "<unknown>")
            
            # Check 1: Known system processes with wrong parents
            if name in self.SUSPICIOUS_PARENTS:
                expected_parents = self.SUSPICIOUS_PARENTS[name]
                if parent_name not in expected_parents and parent_name != "<unknown>":
                    findings.append({
                        "pid": pid,
                        "process_name": name,
                        "threat_label": "ANOMALOUS_PARENT",
                        "description": f"{name} was spawned by {parent_name} (expected one of: {expected_parents})",
                        "risk_score": 85
                    })
                    
            # Check 2: Critical processes spawning shells
            if parent_name in self.NO_SHELL_PARENTS and name in self.SHELLS:
                findings.append({
                    "pid": pid,
                    "process_name": name,
                    "threat_label": "SYSTEM_PROCESS_SPAWNED_SHELL",
                    "description": f"Critical system process {parent_name} spawned a shell ({name})",
                    "risk_score": 95
                })
                
        return roots, children_map, findings

    def render_tree(self) -> List[Dict]:
        """Renders the tree to the console and returns findings."""
        self.console.print(Panel(
            "[bold cyan]Process Tree Analyzer[/bold cyan]\n"
            "[dim]Mapping process lineage and detecting anomalous child processes[/dim]",
            border_style="cyan", box=box.ROUNDED, expand=False
        ))
        
        roots, children_map, findings = self.analyze_tree()
        
        # Build rich tree
        tree = Tree("[bold white]System Process Tree[/bold white]")
        
        def add_nodes(parent_tree, procs):
            for p in sorted(procs, key=lambda x: x["pid"]):
                name = p["name"]
                pid = p["pid"]
                
                # Check if this process has a finding
                has_finding = any(f["pid"] == pid for f in findings)
                style = "bold red" if has_finding else "white"
                
                node_text = Text(f"{name} (PID: {pid})", style=style)
                if has_finding:
                    node_text.append(" [!] ANOMALY DETECTED", style="bold red blink")
                    
                node = parent_tree.add(node_text)
                
                if p["pid"] in children_map and children_map[p["pid"]]:
                    add_nodes(node, children_map[p["pid"]])
                    
        add_nodes(tree, roots)
        
        self.console.print(tree)
        self.console.print()
        
        if findings:
            self.console.print(f"[bold red][!] Detected {len(findings)} anomalous process relationship(s).[/bold red]")
            for f in findings:
                self.console.print(f"  - [red]{f['description']}[/red] (Risk: {f['risk_score']})")
        else:
            self.console.print("[bold green][+] No anomalous process relationships detected.[/bold green]")
            
        return findings

if __name__ == "__main__":
    builder = ProcessTreeBuilder()
    builder.render_tree()
