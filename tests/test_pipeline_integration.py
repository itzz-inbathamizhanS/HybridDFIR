import pytest
import os
import json
from unittest.mock import patch, MagicMock
from pathlib import Path
from src.main import run_pipeline
from src.config.settings import OUTPUT_DIR

@patch("src.main.ReportGenerator")
@patch("src.memory.volatility_wrapper.subprocess.run")
@patch("src.intake.ingest_image.calculate_hashes")
def test_pipeline_integration(mock_calc_hashes, mock_sub_run, mock_report_gen, tmp_path):
    # 1. Setup mock hashes and dummy file
    mock_calc_hashes.return_value = {
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
    
    dummy_image = tmp_path / "dummy_memory.raw"
    dummy_image.write_bytes(b"dummy data")
    
    # 2. Setup mock memory processes
    mock_sub_run.return_value.stdout = '[{"PID": 1234, "PPID": 456, "ImageFileName": "powershell.exe", "Handles": 150}]'
    mock_sub_run.return_value.returncode = 0
    
    # 3. Setup Report Generator Mock to capture what is passed to it
    mock_gen_instance = MagicMock()
    mock_report_gen.return_value = mock_gen_instance
    mock_gen_instance.generate_json_report.return_value = str(tmp_path / "report.json")
    mock_gen_instance.generate_html_report.return_value = str(tmp_path / "report.html")

    # 4. Execute the pipeline
    run_pipeline(str(dummy_image), "memory", None)
    
    # 5. Verify the results
    # Ensure report generator was instantiated correctly
    mock_report_gen.assert_called_once()
    
    # Extract the argument passed to generate_json_report
    # run_pipeline now passes a Case Object dict (from CaseManager)
    mock_gen_instance.generate_json_report.assert_called_once()
    case_data = mock_gen_instance.generate_json_report.call_args[0][0]
    
    # Assert Evidence Metadata (embedded under "metadata" key)
    metadata = case_data["metadata"]
    assert metadata["image_type"] == "memory"
    assert metadata["size_bytes"] == 10
    assert metadata["hashes"]["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    
    # Assert Findings - the pipeline adds timeline events + threats as findings
    findings = case_data["findings"]
    
    # Should have at least the timeline event for powershell.exe
    timeline_findings = [f for f in findings if f.get("event_type") == "Active Process"]
    assert len(timeline_findings) == 1
    assert timeline_findings[0]["description"] is not None
    assert "powershell.exe" in timeline_findings[0]["description"]
    
    # Should have a threat finding for powershell.exe (suspicious executable, risk_score=60)
    threat_findings = [f for f in findings if f.get("event_type") == "THREAT_DETECTED"]
    assert len(threat_findings) >= 1
    powershell_threats = [t for t in threat_findings if "powershell" in t.get("description", "").lower()]
    assert len(powershell_threats) >= 1
    assert powershell_threats[0]["risk_score"] == 60
