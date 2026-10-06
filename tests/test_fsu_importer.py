import hashlib

import pytest

from src.correlation.threat_scorer import ThreatScorer
from src.hardware.fsu_importer import import_fsu_results
from src.response.report_generator import ReportGenerator

TRACE = (
    "11164413000: system.mem_ctrls: [FSU-ALERT] W^X violation: IFetch addr 0xc8000 on written page 0xc8000\n"
    "11164413000: system.mem_ctrls: [FSU-CR3] Cr3=0x64 (ctx 0)\n"
    "11164413000: system.mem_ctrls: [FSU-EVAC] page 0xc8000 (4096 B) written to m5out/fsu_evidence/0xc8000.bin\n"
    "11164413000: system.mem_ctrls: [FSU-STALL] holding request, context 0 stalled (abstract stall)\n"
    "garbage line that must be ignored\n"
)
PAGE = bytes([0x90, 0x90, 0xC3]) + bytes(4093)


@pytest.fixture
def fsu_dir(tmp_path):
    (tmp_path / "fsu_trace.txt").write_text(TRACE)
    (tmp_path / "stats.txt").write_text(
        "simTicks   11164413000   # t\nsimInsts   140131   # i\nsystem.cpu.ipc   0.006276   # ipc\nother 1\n")
    ev = tmp_path / "fsu_evidence"
    ev.mkdir()
    (ev / "0xc8000.bin").write_bytes(PAGE)
    return tmp_path


def test_events_and_hash(fsu_dir):
    r = import_fsu_results(str(fsu_dir))
    types = [e["event_type"] for e in r["events"]]
    assert types == ["FSU_WX_VIOLATION", "FSU_CR3", "FSU_EVACUATION", "FSU_STALL"]
    assert all(e["source_module"] == "hardware" for e in r["events"])
    assert r["events"][0]["timestamp"] == "SIM+0.011164413s"
    assert r["evidence"][0]["sha256"] == hashlib.sha256(PAGE).hexdigest()
    assert r["evidence"][0]["size"] == 4096
    assert r["stats"] == {"simTicks": "11164413000", "simInsts": "140131", "system.cpu.ipc": "0.006276"}


def test_missing_evidence_is_reported_not_fatal(fsu_dir):
    (fsu_dir / "fsu_evidence" / "0xc8000.bin").unlink()
    r = import_fsu_results(str(fsu_dir))
    assert r["evidence"][0]["sha256"] is None
    assert "not found" in r["events"][2]["description"]


def test_missing_trace_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        import_fsu_results(str(tmp_path))


def test_scorer_gives_hardware_alert_max_score(fsu_dir):
    r = import_fsu_results(str(fsu_dir))
    threats = ThreatScorer().evaluate_timeline(r["events"])
    assert len(threats) == 1
    assert threats[0]["risk_score"] == 100 and threats[0]["source_module"] == "hardware"


def test_html_report_has_hardware_section(fsu_dir, tmp_path, monkeypatch):
    import src.response.report_generator as rg
    monkeypatch.setattr(rg, "OUTPUT_DIR", tmp_path / "out")
    r = import_fsu_results(str(fsu_dir))
    data = {"evidence_metadata": {}, "timeline": r["events"],
            "threats": ThreatScorer().evaluate_timeline(r["events"]), "hardware": r}
    path = ReportGenerator("t").generate_html_report(data)
    html = open(path, encoding="utf-8").read()
    assert "Hardware layer (FSU)" in html and hashlib.sha256(PAGE).hexdigest() in html
