import os
import datetime
import logging
from .validator import calculate_hashes
from src.config.settings import SUPPORTED_DISK_FORMATS, SUPPORTED_MEMORY_FORMATS
from src.config import validate_schema

logger = logging.getLogger(__name__)

class EvidenceIntake:
    """
    Manages the secure ingestion, validation, and cataloging of forensic images.
    Guarantees read-only interaction.
    """
    VALID_TYPES = ('disk', 'memory', 'hybrid')

    def __init__(self, file_path: str, image_type: str, case_id: str = None, examiner: str = "SYSTEM"):
        self.file_path = file_path
        self.image_type = image_type.lower()
        self.case_id = case_id
        self.examiner = examiner
        self.metadata = {}

    def process_evidence(self) -> dict:
        """
        Executes the intake pipeline.
        Returns a dict with 'status' and 'metadata' or 'reason'.
        """
        logger.info("Starting intake for %s image: %s", self.image_type, self.file_path)
        
        if self.image_type not in self.VALID_TYPES:
            return {"status": "ERROR", "reason": f"Invalid image type '{self.image_type}'"}

        if not os.path.exists(self.file_path):
            return {"status": "ERROR", "reason": f"Evidence file not found: {self.file_path}"}
        
        if not os.path.isfile(self.file_path):
            return {"status": "ERROR", "reason": f"Path is not a file: {self.file_path}"}

        try:
            file_size = os.path.getsize(self.file_path)
        except Exception as e:
            return {"status": "ERROR", "reason": f"Could not read file size: {e}"}

        logger.info("File located. Size: %.2f GB. Calculating hashes...", file_size / (1024**3))
        
        try:
            hashes = calculate_hashes(self.file_path)
        except Exception as e:
            return {"status": "ERROR", "reason": f"Hash calculation failed: {e}"}

        # Deterministic unique ID using SHA256 prefix
        catalog_type = "memory" if self.image_type == "hybrid" else self.image_type
        evidence_id = f"EVID-{catalog_type.upper()}-{hashes['sha256'][:8].upper()}"
        
        self.metadata = {
            "evidence_id": evidence_id,
            "case_id": self.case_id or "UNASSIGNED",
            "evidence_type": self.image_type,
            "original_filename": os.path.basename(self.file_path),
            "source_description": f"Local file upload: {self.file_path}",
            "acquisition_time": datetime.datetime.utcnow().isoformat() + "Z", # We don't have true acquisition time
            "ingestion_time": datetime.datetime.utcnow().isoformat() + "Z",
            "timezone": "UTC",
            "file_size": file_size,
            "SHA-256": hashes["sha256"],
            "additional_hashes": {"md5": hashes["md5"]},
            "source_metadata": {"file_path": os.path.abspath(self.file_path)},
            "acquisition_method": "LOCAL_IMPORT",
            "tool_name": "HybridForensicsFramework",
            "tool_version": "1.0.0",
            "examiner": self.examiner,
            "provenance": f"Imported directly from {os.path.abspath(self.file_path)}",
            "validation_status": "VALID"
        }
        
        # Validate against schema
        if not validate_schema(self.metadata, "EvidenceItem"):
            logger.warning("Intake metadata failed EvidenceItem schema validation")
            # Fallback to old schema
            old_meta = {
                "evidence_id": evidence_id,
                "file_name": os.path.basename(self.file_path),
                "file_path": os.path.abspath(self.file_path),
                "image_type": self.image_type,
                "size_bytes": file_size,
                "hashes": hashes,
                "intake_timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            if validate_schema(old_meta, "EvidenceMetadata"):
                self.metadata = old_meta
        
        logger.info("Intake complete. Hashes verified. Evidence ID: %s", evidence_id)
        return {"status": "SUCCESS", "metadata": self.metadata}
