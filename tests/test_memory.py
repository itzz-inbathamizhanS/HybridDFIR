import pytest
from unittest.mock import patch
from src.memory.process_scanner import ProcessScanner

@patch("src.memory.volatility_wrapper.subprocess.run")
def test_extract_running_processes(mock_run, tmp_path):
    # Mock the JSON output from Volatility 3
    mock_run.return_value.stdout = '[{"PID": 1234, "PPID": 456, "ImageFileName": "cmd.exe", "Handles": 150}]'
    mock_run.return_value.returncode = 0
    
    # Create a temporary dummy file on disk so the VolatilityWrapper file check passes
    dummy_file = tmp_path / "dummy_memory.raw"
    dummy_file.touch()
    
    # Pass the path of the newly created dummy file
    scanner = ProcessScanner(str(dummy_file))
    processes = scanner.extract_running_processes()
    
    assert len(processes) == 1
    assert processes[0]["pid"] == 1234
    assert processes[0]["process_name"] == "cmd.exe"
    assert processes[0]["handles_count"] == 150