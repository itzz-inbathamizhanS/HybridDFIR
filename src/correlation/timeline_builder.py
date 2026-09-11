import datetime
import json
import logging

from src.config.settings import OUTPUT_DIR

logger = logging.getLogger(__name__)

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
                "timestamp": item.get("timestamp") or "UNKNOWN",
                "source_module": "disk",
                "event_type": item.get("artifact_type", "Unknown Disk Event"),
                "description": f"Found at: {item.get('source_path')}",
                "risk_score": 0,
                "raw_data": item
            })
        logger.info("Ingested %d disk artifacts into timeline", len(artifacts))

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
                "risk_score": 0,
                "raw_data": proc
            })
        logger.info("Ingested %d memory processes into timeline", len(processes))

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
        
        logger.info(
            "Built timeline: %d dated events + %d undated events",
            len(dated_events), len(unknown_events)
        )
        return dated_events + unknown_events

    def add_events(self, events: list):
        """
        Add pre-formatted CorrelatedEvent dicts directly into the timeline.
        Used by the CLI --scan path and the unified dashboard.
        """
        for event in events:
            self.master_timeline.append({
                "timestamp": event.get("timestamp", datetime.datetime.utcnow().isoformat() + "Z"),
                "source_module": event.get("source_module", "memory"),
                "event_type": event.get("event_type", "THREAT_DETECTED"),
                "description": event.get("description", ""),
                "risk_score": event.get("risk_score", 0),
                "raw_data": event,
            })
        logger.info("Added %d pre-formatted events to timeline", len(events))

    def save_timeline(self, filename: str) -> str:
        """
        Save the current timeline to a JSON file in the output directory.

        Returns the full path to the saved file.
        """
        timeline = self.build_timeline()
        output_path = OUTPUT_DIR / filename
        with open(output_path, "w", encoding="utf-8") as fp:
            json.dump({
                "timeline_events": len(timeline),
                "generated_utc": datetime.datetime.utcnow().isoformat() + "Z",
                "events": timeline,
            }, fp, indent=2, default=str)
        logger.info("Saved timeline with %d events to %s", len(timeline), output_path)
        return str(output_path)

    def get_timeline(self) -> list:
        """Return the raw master timeline without sorting (for aggregation)."""
        return self.master_timeline