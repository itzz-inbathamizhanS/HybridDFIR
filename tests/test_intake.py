import pytest
from src.intake.ingest_image import EvidenceIntake

def test_evidence_intake_success(tmp_path):
    # Create a temporary dummy evidence file
    dummy_file = tmp_path / "memdump.raw"
    dummy_file.write_bytes(b"simulated_forensic_data_block")
    
    intake = EvidenceIntake(file_path=str(dummy_file), image_type="memory")
    metadata = intake.process_evidence()
    
    assert metadata["image_type"] == "memory"
    assert metadata["size_bytes"] == len(b"simulated_forensic_data_block")
    assert "md5" in metadata["hashes"]
    assert "sha256" in metadata["hashes"]
    assert "intake_timestamp_utc" in metadata

def test_evidence_intake_invalid_type(tmp_path):
    dummy_file = tmp_path / "disk.dd"
    dummy_file.touch()
    
    with pytest.raises(ValueError, match="Invalid image type"):
        EvidenceIntake(file_path=str(dummy_file), image_type="network")