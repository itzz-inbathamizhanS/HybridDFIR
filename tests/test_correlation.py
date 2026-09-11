import pytest
from src.correlation.threat_scorer import ThreatScorer

def test_threat_scorer_detects_malware():
    scorer = ThreatScorer()
    
    # Simulate a suspicious prefetch artifact and a benign process
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
                "path": "C:\\Windows\\System32",
                "ppid": 512  # Valid parent PID (services.exe)
            }
        }
    ]
    
    threats = scorer.evaluate_timeline(dummy_timeline)
    
    # Only mimikatz should be flagged (svchost with valid parent is clean)
    assert len(threats) == 1
    assert threats[0]["risk_score"] == 75
    assert "mimikatz" in threats[0]["description"].lower()
    assert threats[0]["source_module"] == "disk"


def test_threat_scorer_detects_suspicious_process():
    scorer = ThreatScorer()
    
    dummy_timeline = [
        {
            "timestamp": "2023-10-01T12:00:00Z",
            "source_module": "memory",
            "event_type": "Active Process",
            "raw_data": {
                "process_name": "powershell.exe",
                "path": "C:\\Users\\Public\\Downloads",
                "ppid": 100
            }
        }
    ]
    
    threats = scorer.evaluate_timeline(dummy_timeline)
    
    # Should flag for: suspicious exe (60) + suspicious path (40) = 100
    assert len(threats) >= 1
    assert threats[0]["risk_score"] == 100  # Capped at 100
    assert "powershell" in threats[0]["description"].lower()


def test_threat_scorer_mitre_mapping():
    scorer = ThreatScorer()
    
    dummy_timeline = [
        {
            "timestamp": "2023-10-01T12:00:00Z",
            "source_module": "disk",
            "event_type": "Prefetch File",
            "raw_data": {
                "details": {"executable_identified": "psexec.exe"}
            }
        }
    ]
    
    threats = scorer.evaluate_timeline(dummy_timeline)
    
    assert len(threats) >= 1
    # Should have MITRE ATT&CK TTPs
    assert "mitre_attack_ttps" in threats[0]
    assert "T1570" in threats[0]["mitre_attack_ttps"]  # Lateral Tool Transfer


def test_threat_scorer_parent_child_anomaly():
    scorer = ThreatScorer()
    
    # svchost.exe with ppid=0 is anomalous (should be spawned by services.exe)
    dummy_timeline = [
        {
            "timestamp": "2023-10-01T12:00:00Z",
            "source_module": "memory",
            "event_type": "Active Process",
            "raw_data": {
                "process_name": "svchost.exe",
                "path": "C:\\Windows\\System32\\svchost.exe",
                "ppid": 0
            }
        }
    ]
    
    threats = scorer.evaluate_timeline(dummy_timeline)
    
    assert len(threats) >= 1
    assert any("anomalous parent" in t["description"].lower() for t in threats)


def test_threat_scorer_clean_process():
    scorer = ThreatScorer()
    
    dummy_timeline = [
        {
            "timestamp": "2023-10-01T12:00:00Z",
            "source_module": "memory",
            "event_type": "Active Process",
            "raw_data": {
                "process_name": "notepad.exe",
                "path": "C:\\Windows\\System32\\notepad.exe",
                "ppid": 1234
            }
        }
    ]
    
    threats = scorer.evaluate_timeline(dummy_timeline)
    
    # Notepad should NOT be flagged
    assert len(threats) == 0


def test_threat_scorer_risk_score_capping():
    scorer = ThreatScorer()
    
    # A process that triggers multiple rules should be capped at 100
    dummy_timeline = [
        {
            "timestamp": "2023-10-01T12:00:00Z",
            "source_module": "memory",
            "event_type": "Active Process",
            "raw_data": {
                "process_name": "mimikatz.exe",
                "path": "C:\\Users\\Public\\Downloads\\temp",
                "ppid": 0
            }
        }
    ]
    
    threats = scorer.evaluate_timeline(dummy_timeline)
    
    assert len(threats) >= 1
    # Risk should be capped at 100 regardless of how many rules trigger
    assert all(t["risk_score"] <= 100 for t in threats)