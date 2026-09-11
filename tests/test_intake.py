import os
import pytest
from unittest.mock import patch
from src.intake.ingest_image import EvidenceIntake

def test_evidence_intake_success(tmp_path):
    test_file = tmp_path / "test_image.raw"
    test_file.write_text("fake forensic data for hashing test")
    
    intake = EvidenceIntake(str(test_file), "disk")
    result = intake.process_evidence()
    
    assert result["file_name"] == "test_image.raw"
    assert "hashes" in result
    assert "md5" in result["hashes"]
    assert "sha256" in result["hashes"]
    assert result["image_type"] == "disk"


def test_evidence_intake_invalid_type():
    with pytest.raises(ValueError, match="Invalid image type"):
        EvidenceIntake("/fake/path.raw", "invalid_type")


def test_evidence_intake_hybrid_type(tmp_path):
    """Hybrid mode should be accepted and normalize evidence_id to memory."""
    test_file = tmp_path / "test_hybrid.raw"
    test_file.write_text("fake hybrid forensic data")
    
    intake = EvidenceIntake(str(test_file), "hybrid")
    result = intake.process_evidence()
    
    assert result["image_type"] == "hybrid"
    # evidence_id should be normalized to memory_ prefix
    assert result["evidence_id"].startswith("memory_")


def test_evidence_intake_memory_type(tmp_path):
    test_file = tmp_path / "test_mem.vmem"
    test_file.write_text("fake memory dump data")
    
    intake = EvidenceIntake(str(test_file), "memory")
    result = intake.process_evidence()
    
    assert result["image_type"] == "memory"
    assert result["evidence_id"].startswith("memory_")


def test_evidence_intake_file_not_found():
    intake = EvidenceIntake("/nonexistent/path/file.raw", "disk")
    with pytest.raises(FileNotFoundError):
        intake.process_evidence()


def test_evidence_intake_metadata_fields(tmp_path):
    """Verify all required metadata fields are present."""
    test_file = tmp_path / "test_complete.raw"
    test_file.write_text("complete metadata test data")
    
    intake = EvidenceIntake(str(test_file), "disk")
    result = intake.process_evidence()
    
    required_fields = ["evidence_id", "file_name", "file_path", "image_type",
                       "size_bytes", "hashes", "intake_timestamp_utc"]
    for field in required_fields:
        assert field in result, f"Missing required field: {field}"
    
    assert isinstance(result["size_bytes"], int)
    assert result["size_bytes"] > 0