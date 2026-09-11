import json
import datetime
from src.config.settings import OUTPUT_DIR

class AuditLog:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.log_file = OUTPUT_DIR / case_id / "audit_log.json"
        
        if not self.log_file.exists() and (OUTPUT_DIR / case_id).exists():
            with open(self.log_file, "w", encoding="utf-8") as f:
                json.dump([], f)

    def log_action(self, actor: str, action: str, obj: str, reason: str = "", previous_state: dict = None, resulting_state: dict = None):
        if not self.log_file.exists():
            return
            
        record = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat() + "Z",
            "actor": actor,
            "action": action,
            "object": obj,
            "reason": reason,
            "previous_state": previous_state or {},
            "resulting_state": resulting_state or {}
        }
        
        with open(self.log_file, "r+", encoding="utf-8") as f:
            try:
                logs = json.load(f)
            except:
                logs = []
            logs.append(record)
            f.seek(0)
            json.dump(logs, f, indent=4)
            f.truncate()
            
    def get_logs(self):
        if not self.log_file.exists():
            return []
        with open(self.log_file, "r", encoding="utf-8") as f:
            return json.load(f)
