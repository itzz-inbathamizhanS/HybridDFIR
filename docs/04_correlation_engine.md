# Correlation Engine

> Module: `src/correlation/` — Timeline Building & Threat Scoring

---

## 1. Overview

The Correlation Engine is the brain of the Hybrid Forensics Framework. It is responsible for bridging the gap between disk artifacts and memory processes. 

Instead of treating disk and memory as isolated silos, this module:
1. Merges all parsed artifacts into a single chronological timeline
2. Evaluates the timeline against heuristic rulesets
3. Outputs standardized `CorrelatedEvent` objects with calculated risk scores

---

## 2. Module Structure

```
src/correlation/
├── __init__.py                # Exports: TimelineBuilder, ThreatScorer
├── timeline_builder.py        # Chronological sorting and event merging
└── threat_scorer.py           # Rule-based heuristic risk evaluation
```

---

## 3. Core Components

### 3.1 `TimelineBuilder` Class

**File:** `src/correlation/timeline_builder.py`

Responsible for unifying disparate forensic artifacts into a single, time-ordered sequence of events.

#### `ingest_disk_artifacts(artifacts: list)`

Accepts formatted `DiskArtifact` objects (produced by `ArtifactExtractor`) and maps them to a generic timeline schema.

```python
# Disk artifact ingestion logic
self.master_timeline.append({
    "timestamp": item.get("timestamp"),
    "source_module": "disk",
    "event_type": item.get("artifact_type", "Unknown Disk Event"),
    "description": f"Found at: {item.get('source_path')}",
    "raw_data": item
})
```

#### `ingest_memory_processes(processes: list, intake_time: str)`

Accepts formatted `MemoryProcess` objects. Because volatile memory processes often lack discrete creation timestamps in basic snapshot plugins, the engine intelligently anchors these events to the overall forensic intake/dump timestamp.

```python
# Memory process ingestion logic
self.master_timeline.append({
    "timestamp": intake_time,
    "source_module": "memory",
    "event_type": "Active Process",
    "description": f"Process {proc.get('process_name')} (PID: {proc.get('pid')}) running in memory.",
    "raw_data": proc
})
```

#### `build_timeline() → list`

Chronologically sorts the `master_timeline` by UTC timestamp.
Events with `UNKNOWN` timestamps (e.g., deleted files or damaged MAC times) are safely filtered, deferred, and appended to the end of the timeline so they are not lost.

---

### 3.2 `ThreatScorer` Class

**File:** `src/correlation/threat_scorer.py`

Evaluates the unified timeline against heuristic rules to identify anomalies, lateral movement indicators, and execution of malicious payloads.

#### Internal Rulesets

```python
self.suspicious_executables = ["cmd.exe", "powershell.exe", "mimikatz.exe", "psexec.exe"]
self.suspicious_paths       = ["temp", "appdata", "downloads"]
```

#### `evaluate_timeline(timeline: list) → list`

Iterates over every event in the chronological timeline and evaluates it against multi-source rules.

**Rule 1: Suspicious Disk Prefetch**
- Checks if a `Prefetch File` artifact references an executable in the `suspicious_executables` list.
- **Action:** Assigns Risk Score 75.

**Rule 2: Suspicious Memory Processes**
- Checks if an `Active Process` matches `suspicious_executables`.
- **Action:** Adds +60 to Risk Score.
- Checks if the process path is running from an unusual directory (`suspicious_paths`).
- **Action:** Adds +40 to Risk Score.

*Note: Native Live RAM scanning (`src/capture/native_ram.py`) performs its own deep memory heuristics (e.g., `RWX_SHELLCODE_INJECTION` = 90) and passes them directly to the `CorrelatedEvent` schema.*

#### Risk Score Capping

Risk scores are strictly capped to a maximum of 100 to comply with the JSON Schema validation rules.

```python
final_score = min(risk_score, 100)
```

---

## 4. Data Schema

The `ThreatScorer` formats all flagged anomalies as `CorrelatedEvent` objects, strictly enforcing the framework's JSON Schema (`src/config/data_models.json`):

```json
{
  "type": "object",
  "required": ["timestamp", "source_module", "event_type", "description", "risk_score"],
  "properties": {
    "timestamp": { "type": "string" },
    "source_module": { "type": "string", "enum": ["disk", "memory", "intake"] },
    "event_type": { "type": "string" },
    "description": { "type": "string" },
    "risk_score": { "type": "integer", "minimum": 0, "maximum": 100 }
  }
}
```

**Example Output Payload:**

```json
{
  "timestamp": "2026-08-23T16:02:11+00:00",
  "source_module": "memory",
  "event_type": "THREAT_DETECTED",
  "description": "High-risk process actively running: powershell.exe. Running from unusual directory: c:\\users\\public\\downloads.",
  "risk_score": 100
}
```

---

## 5. Usage Example

```python
from src.correlation import TimelineBuilder, ThreatScorer

# 1. Build the timeline from extracted artifacts
builder = TimelineBuilder()
builder.ingest_disk_artifacts(disk_artifacts)
builder.ingest_memory_processes(memory_processes, intake_metadata["intake_timestamp_utc"])
unified_timeline = builder.build_timeline()

# 2. Score threats
scorer = ThreatScorer()
threats = scorer.evaluate_timeline(unified_timeline)

print(f"Found {len(threats)} high-risk anomalies.")
for threat in threats:
    print(f"[{threat['risk_score']}/100] {threat['description']}")
```

---

## 6. Test Coverage

The correlation module is covered by `tests/test_correlation.py`:

| Test Case | Description |
|---|---|
| `test_threat_scorer_detects_malware` | Feeds a simulated timeline containing a benign process (`svchost.exe`) and a malicious prefetch (`mimikatz.exe`) into the scorer. Asserts that only `mimikatz` is flagged with the correct risk score. |

Run tests:
```bash
pytest tests/test_correlation.py -v
```

---

*Document version: 1.0 — August 2026*
