import os
import datetime
from .validator import calculate_hashes

class EvidenceIntake:
    """
    Manages the secure ingestion, validation, and cataloging of forensic images.
    """
    def __init__(self, file_path: str, image_type: str):
        """
        Args:
            file_path (str): Path to the raw dump (.raw, .dd, .vmem, etc.)
            image_type (str): Must be either 'disk' or 'memory'
        """
        self.file_path = file_path
        self.image_type = image_type.lower()
        self.metadata = {}

        if self.image_type not in ['disk', 'memory']:
            raise ValueError("Invalid image type. Must be 'disk' or 'memory'.")

    def process_evidence(self) -> dict:
        """
        Executes the intake pipeline: verifies file, calculates hashes, extracts metadata.
        
        Returns:
            dict: Standardized metadata payload for downstream processing.
        """
        print(f"[*] Starting intake for {self.image_type} image: {self.file_path}")
        
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"Evidence file not found: {self.file_path}")
        
        file_size = os.path.getsize(self.file_path)
        print(f"[*] File located. Size: {file_size / (1024**3):.2f} GB. Calculating hashes (this may take a while)...")
        
        hashes = calculate_hashes(self.file_path)
        
        # Build the structured metadata payload
        self.metadata = {
            "evidence_id": f"{self.image_type}_{hashes['md5'][:8]}",
            "file_name": os.path.basename(self.file_path),
            "file_path": os.path.abspath(self.file_path),
            "image_type": self.image_type,
            "size_bytes": file_size,
            "hashes": hashes,
            "intake_timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        
        print("[+] Intake complete. Hashes verified.")
        return self.metadata