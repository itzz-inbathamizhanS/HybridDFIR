import logging
from .volatility_wrapper import VolatilityWrapper

logger = logging.getLogger(__name__)

class ProcessScanner:
    """
    Scans memory dumps for active and hidden processes, formatting the output
    to match the framework's strict Data Models.
    """
    def __init__(self, memory_image_path: str):
        self.wrapper = VolatilityWrapper(memory_image_path)

    def extract_running_processes(self) -> dict:
        """
        Extracts all running processes and formats them into the MemoryProcess schema.
        Returns a dict with 'status', 'reason', and 'processes'.
        """
        logger.info("Running Volatility 3 windows.pslist plugin...")
        result = self.wrapper.run_plugin("windows.pslist.PsList")
        
        if result["status"] != "SUCCESS":
            return {"status": result["status"], "reason": result["reason"], "processes": []}
            
        raw_processes = result["data"]
        formatted_processes = []
        
        for proc in raw_processes:
            formatted_processes.append({
                "pid": proc.get("PID", 0),
                "ppid": proc.get("PPID", 0),
                "process_name": proc.get("ImageFileName", "Unknown"),
                "path": proc.get("ImageFileName", "Unknown"), 
                "handles_count": proc.get("Handles", 0)
            })
            
        logger.info("Extracted %d processes from memory.", len(formatted_processes))
        return {"status": "SUCCESS", "reason": "OK", "processes": formatted_processes}
        
    def check_for_injected_code(self) -> dict:
        """
        Runs the malfind plugin to detect injected/hidden code in memory.
        """
        logger.info("Running Volatility 3 windows.malfind plugin...")
        result = self.wrapper.run_plugin("windows.malfind.Malfind")
        logger.info("Malfind returned status %s", result["status"])
        return result