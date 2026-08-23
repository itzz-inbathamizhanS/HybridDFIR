import os
import sys
import time
import ctypes
import subprocess
from rich.console import Console

console = Console()

class LiveRAMCapturer:
    """Handles kernel-level interaction to dump live physical memory."""
    def __init__(self, output_dir="output"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        # Name the capture file based on the current timestamp
        self.dump_path = os.path.join(self.output_dir, f"live_capture_{int(time.time())}.raw")
        self.winpmem_path = os.path.join(os.getcwd(), "winpmem.exe")

    def is_admin(self) -> bool:
        """Check if the script is running with administrative privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def capture_memory(self) -> str:
        """Executes the kernel driver to snapshot RAM."""
        if not self.is_admin():
            console.print("[bold red]✖ CRITICAL ERROR: Live RAM capture requires Administrator privileges![/bold red]")
            console.print("[yellow]Please close PowerShell, right-click it, select 'Run as Administrator', and try again.[/yellow]")
            sys.exit(1)

        if not os.path.exists(self.winpmem_path):
            console.print(f"[bold red]✖ Missing Capture Driver: Could not find {self.winpmem_path}[/bold red]")
            console.print("[yellow]Please download winpmem.exe and place it in the project root folder.[/yellow]")
            sys.exit(1)

        console.print(f"[bold blue]Loading kernel driver and capturing live RAM to {self.dump_path}...[/bold blue]")
        
        # Run winpmem to capture memory
        cmd = [self.winpmem_path, "-o", self.dump_path]
        
        try:
            # We don't capture output here so the user can see WinPmem's native progress bar
            subprocess.run(cmd, check=True)
            console.print("[bold green]✔ Live Memory Snapshot Completed Successfully.[/bold green]")
            return self.dump_path
        except subprocess.CalledProcessError as e:
            console.print(f"[bold red]✖ RAM Capture Failed: {e}[/bold red]")
            sys.exit(1)