import json
import uuid
import datetime
from src.config.settings import OUTPUT_DIR

class CaseManager:
    def __init__(self, case_id: str = None):
        self.case_id = case_id
        self.case_data = None
        self.case_dir = None
        if self.case_id:
            self.case_dir = OUTPUT_DIR / self.case_id
            self.load_case()

    def create_case(self, case_name: str, analyst: str, description: str = "", organization: str = "", classification: str = "UNCLASSIFIED", priority: str = "NORMAL") -> str:
        self.case_id = f"CASE-{datetime.datetime.now(datetime.UTC).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        self.case_dir = OUTPUT_DIR / self.case_id
        self.case_dir.mkdir(parents=True, exist_ok=True)
        
        self.case_data = {
            "case_id": self.case_id,
            "case_name": case_name,
            "case_description": description,
            "creation_time": datetime.datetime.now(datetime.UTC).isoformat() + "Z",
            "analyst": analyst,
            "organization": organization,
            "classification_label": classification,
            "case_status": "NEW",
            "priority": priority,
            "investigation_start": datetime.datetime.now(datetime.UTC).isoformat() + "Z",
            "investigation_end": None,
            "timezone": "UTC",
            "evidence_items": [],
            "findings": [],
            "indicators": [],
            "entities": [],
            "relationships": [],
            "analyst_notes": []
        }
        self.save_case()
        return self.case_id

    def load_case(self):
        if not self.case_dir.exists():
            raise FileNotFoundError(f"Case directory not found: {self.case_id}")
        case_file = self.case_dir / "case.json"
        if not case_file.exists():
            raise FileNotFoundError(f"case.json not found in {self.case_id}")
        with open(case_file, "r", encoding="utf-8") as f:
            self.case_data = json.load(f)

    def save_case(self):
        if not self.case_data or not self.case_dir:
            return
        case_file = self.case_dir / "case.json"
        with open(case_file, "w", encoding="utf-8") as f:
            json.dump(self.case_data, f, indent=4)

    def update_status(self, new_status: str):
        valid_statuses = ["NEW", "TRIAGE", "INVESTIGATION", "REVIEW", "CONFIRMED", "DISMISSED", "CLOSED", "ARCHIVED"]
        if new_status not in valid_statuses:
            raise ValueError(f"Invalid status: {new_status}")
        self.case_data["case_status"] = new_status
        if new_status in ["CLOSED", "ARCHIVED"]:
            self.case_data["investigation_end"] = datetime.datetime.now(datetime.UTC).isoformat() + "Z"
        self.save_case()

    def add_evidence(self, evidence_id: str):
        if evidence_id not in self.case_data["evidence_items"]:
            self.case_data["evidence_items"].append(evidence_id)
            self.save_case()
            
    def add_finding(self, finding: dict):
        self.case_data["findings"].append(finding)
        self.save_case()
        
    def add_relationship(self, source_id: str, target_id: str, relationship_type: str, confidence: str):
        valid_confidences = ["LOW", "MEDIUM", "HIGH", "CERTAIN"]
        if confidence not in valid_confidences:
            confidence = "MEDIUM"
        
        relationship = {
            "relationship_id": f"REL-{uuid.uuid4().hex[:8].upper()}",
            "source_id": source_id,
            "target_id": target_id,
            "relationship_type": relationship_type,
            "confidence": confidence,
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat() + "Z"
        }
        self.case_data["relationships"].append(relationship)
        self.save_case()
            
    def get_case_info(self):
        return self.case_data

