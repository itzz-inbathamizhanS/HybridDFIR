import datetime

class TimelineBuilder:
    """
    Ingests artifacts across multiple forensic modules and builds a unified 
    chronological timeline of events.
    """
    def __init__(self):
        self.master_timeline = []

    def ingest_disk_artifacts(self, artifacts: list):
        """Adds formatted disk artifacts to the timeline."""
        for item in artifacts:
            self.master_timeline.append({
                "timestamp": item.get("timestamp"),
                "source_module": "disk",
                "event_type": item.get("artifact_type", "Unknown Disk Event"),
                "description": f"Found at: {item.get('source_path')}",
                "raw_data": item
            })

    def ingest_memory_processes(self, processes: list, intake_time: str):
        """
        Adds running memory processes. Since raw processes might lack specific 
        start times in a basic pslist, we anchor them to the intake/dump time.
        """
        for proc in processes:
            self.master_timeline.append({
                "timestamp": intake_time,
                "source_module": "memory",
                "event_type": "Active Process",
                "description": f"Process {proc.get('process_name')} (PID: {proc.get('pid')}) running in memory.",
                "raw_data": proc
            })

    def build_timeline(self) -> list:
        """
        Sorts all ingested events chronologically based on their UTC timestamps.
        
        Returns:
            list: A chronologically sorted list of system events.
        """
        # Filter out events with UNKNOWN timestamps before sorting, append them at the end
        dated_events = [e for e in self.master_timeline if e["timestamp"] != "UNKNOWN"]
        unknown_events = [e for e in self.master_timeline if e["timestamp"] == "UNKNOWN"]
        
        # Sort dated events chronologically
        dated_events.sort(key=lambda x: x["timestamp"])
        
        return dated_events + unknown_events