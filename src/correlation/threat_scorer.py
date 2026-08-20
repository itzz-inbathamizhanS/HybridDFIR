class ThreatScorer:
    """
    Analyzes timeline events to identify anomalies, assigning risk scores 
    and generating standard CorrelatedEvent objects.
    """
    def __init__(self):
        self.correlated_threats = []
        
        # Basic Heuristic Ruleset
        self.suspicious_executables = ["cmd.exe", "powershell.exe", "mimikatz.exe", "psexec.exe"]
        self.suspicious_paths = ["temp", "appdata", "downloads"]

    def evaluate_timeline(self, timeline: list) -> list:
        """
        Iterates through the timeline to flag suspicious behaviors.
        """
        for event in timeline:
            raw_data = event.get("raw_data", {})
            risk_score = 0
            threat_description = ""
            
            # Rule 1: Suspicious Disk Prefetch
            if event["source_module"] == "disk" and event["event_type"] == "Prefetch File":
                exe_name = raw_data.get("details", {}).get("executable_identified", "").lower()
                if exe_name in self.suspicious_executables:
                    risk_score = 75
                    threat_description = f"Suspicious executable executed: {exe_name}"
            
            # Rule 2: Suspicious Memory Processes
            elif event["source_module"] == "memory" and event["event_type"] == "Active Process":
                proc_name = raw_data.get("process_name", "").lower()
                path = raw_data.get("path", "").lower()
                
                if proc_name in self.suspicious_executables:
                    risk_score += 60
                    threat_description = f"High-risk process actively running: {proc_name}. "
                
                if any(suspicious_dir in path for suspicious_dir in self.suspicious_paths):
                    risk_score += 40
                    threat_description += f"Running from unusual directory: {path}."
            
            # If a threat was detected, format it strictly to the CorrelatedEvent schema
            if risk_score > 0:
                # Cap risk score at 100 per the JSON schema rules
                final_score = min(risk_score, 100)
                
                self.correlated_threats.append({
                    "timestamp": event.get("timestamp"),
                    "source_module": event.get("source_module"),
                    "event_type": "THREAT_DETECTED",
                    "description": threat_description.strip(),
                    "risk_score": final_score
                })
                
        return self.correlated_threats