from .volatility_wrapper import VolatilityWrapper

class ProcessScanner:
    """
    Scans memory dumps for active and hidden processes, formatting the output
    to match the framework's strict Data Models.
    """
    def __init__(self, memory_image_path: str):
        self.wrapper = VolatilityWrapper(memory_image_path)

    def extract_running_processes(self) -> list:
        """
        Extracts all running processes and formats them into the MemoryProcess schema.
        """
        print("[*] Running Volatility 3 windows.pslist plugin...")
        raw_processes = self.wrapper.run_plugin("windows.pslist.PsList")
        
        formatted_processes = []
        
        for proc in raw_processes:
            # Volatility 3 JSON output maps column names to values.
            # We map these to our strict JSON schema.
            formatted_processes.append({
                "pid": proc.get("PID", 0),
                "ppid": proc.get("PPID", 0),
                "process_name": proc.get("ImageFileName", "Unknown"),
                "path": proc.get("ImageFileName", "Unknown"), # Paths often require deeper plugins
                "handles_count": proc.get("Handles", 0)
            })
            
        print(f"[+] Extracted {len(formatted_processes)} processes from memory.")
        return formatted_processes
        
    def check_for_injected_code(self) -> list:
        """
        Runs the malfind plugin to detect injected/hidden code in memory.
        """
        print("[*] Running Volatility 3 windows.malfind plugin...")
        # Note: malfind output would be mapped similarly depending on correlation needs
        return self.wrapper.run_plugin("windows.malfind.Malfind")