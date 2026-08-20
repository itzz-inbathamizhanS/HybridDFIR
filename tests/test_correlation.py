import pytest
from src.correlation.threat_scorer import ThreatScorer

def test_threat_scorer_detects_malware():
    scorer = ThreatScorer()
    
    # Simulate a suspicious prefetch artifact
    dummy_timeline = [
        {
            "timestamp": "2023-10-01T12:00:00Z",
            "source_module": "disk",
            "event_type": "Prefetch File",
            "raw_data": {
                "details": {"executable_identified": "mimikatz.exe"}
            }
        },
        {
            "timestamp": "2023-10-01T12:05:00Z",
            "source_module": "memory",
            "event_type": "Active Process",
            "raw_data": {
                "process_name": "svchost.exe",
                "path": "C:\\Windows\\System32"
            }
        }
    ]
    
    threats = scorer.evaluate_timeline(dummy_timeline)
    
    # Only mimikatz should be flagged
    assert len(threats) == 1
    assert threats[0]["risk_score"] == 75
    assert "mimikatz" in threats[0]["description"].lower()
    assert threats[0]["source_module"] == "disk"