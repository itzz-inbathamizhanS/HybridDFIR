"""Imports Forensic Snoop Unit (FSU) results from a gem5 run into CorrelatedEvents.

Reads from a results folder:
  fsu_trace.txt            gem5 --debug-flags=FSU output ([FSU-ALERT]/[FSU-CR3]/[FSU-EVAC]/[FSU-STALL])
  stats.txt|fsu_stats.txt  lines for simTicks, simInsts, system.cpu.ipc
  fsu_evidence/*.bin       page dumps (or *.bin directly in the folder), hashed here
Timestamps are SIMULATED time (offset from simulation start), not wall-clock.
"""
import re
from pathlib import Path

from src.intake.validator import calculate_hashes

TICKS_PER_SECOND = 10**12  # gem5 default: 1 tick = 1 ps
_LINE = re.compile(r"^\s*(\d+):\s*(\S+):\s*\[FSU-(ALERT|CR3|EVAC|STALL)\]\s*(.*)$")
_HEX = re.compile(r"0x[0-9a-fA-F]+")
_STAT_KEYS = ("simTicks", "simInsts", "system.cpu.ipc")


def _sim_timestamp(tick: int) -> str:
    return f"SIM+{tick / TICKS_PER_SECOND:.9f}s"


def parse_stats(folder: Path) -> dict:
    stats = {}
    for name in ("stats.txt", "fsu_stats.txt"):
        path = folder / name
        if path.is_file():
            for line in path.read_text(errors="replace").splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] in _STAT_KEYS:
                    stats[parts[0]] = parts[1]
            break
    return stats


def _find_evidence(folder: Path, page: str):
    for base in (folder / "fsu_evidence", folder):
        cand = base / f"{page}.bin"
        if cand.is_file():
            return cand
    return None


def import_fsu_results(folder: str) -> dict:
    """Returns {"events": [CorrelatedEvent], "stats": {...}, "evidence": [...]}.
    Raises FileNotFoundError if fsu_trace.txt is missing."""
    root = Path(folder)
    trace = root / "fsu_trace.txt"
    if not trace.is_file():
        raise FileNotFoundError(f"fsu_trace.txt not found in {root}")

    events, evidence, cr3_by_tick = [], [], {}
    for line in trace.read_text(errors="replace").splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        tick, kind, text = int(m.group(1)), m.group(3), m.group(4).strip()
        raw = {"tick": tick, "kind": kind, "text": text}
        if kind == "ALERT":
            hexes = _HEX.findall(text)
            raw["addr"] = hexes[0] if hexes else None
            raw["page"] = hexes[-1] if hexes else None
            events.append({
                "timestamp": _sim_timestamp(tick), "source_module": "hardware",
                "event_type": "FSU_WX_VIOLATION",
                "description": f"Hardware W^X violation: {text}",
                "risk_score": 0, "raw_data": raw})
        elif kind == "CR3":
            cr3_by_tick[tick] = _HEX.findall(text)[:1]
            events.append({
                "timestamp": _sim_timestamp(tick), "source_module": "hardware",
                "event_type": "FSU_CR3", "description": f"CR3 at alert: {text}",
                "risk_score": 0, "raw_data": raw})
        elif kind == "EVAC":
            page = (_HEX.findall(text) or [None])[0]
            item = {"page": page, "file": None, "sha256": None, "size": None}
            ev = _find_evidence(root, page) if page else None
            if ev:
                h = calculate_hashes(str(ev))
                item.update(file=ev.name, sha256=h["sha256"], size=ev.stat().st_size)
            evidence.append(item)
            raw["evidence"] = item
            events.append({
                "timestamp": _sim_timestamp(tick), "source_module": "hardware",
                "event_type": "FSU_EVACUATION",
                "description": f"Page {page} evacuated"
                               + (f", SHA-256 {item['sha256']}" if item["sha256"] else " (evidence file not found)"),
                "risk_score": 0, "raw_data": raw})
        else:
            events.append({
                "timestamp": _sim_timestamp(tick), "source_module": "hardware",
                "event_type": "FSU_STALL", "description": f"CPU stall: {text}",
                "risk_score": 0, "raw_data": raw})
    return {"events": events, "stats": parse_stats(root), "evidence": evidence}
