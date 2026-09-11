# Correlation Engine

> Module: `src/correlation/` — Timeline Building, Threat Scoring, & Cross-Module Correlation

---

## 1. Overview

The Correlation Engine is the brain of the Hybrid Forensics Framework. It bridges the gap between disparate forensic artifacts, ensuring that network connections, registry persistence, memory regions, and DLLs are not treated as isolated silos.

This module:
1. Merges all parsed artifacts into a single chronological timeline.
2. Evaluates the timeline against heuristic rulesets.
3. Performs deep **Cross-Module Threat Correlation** (Rules 8-12) to detect complex attack chains (e.g., C2 implants).
4. Emits `Relationships` to build the **Evidence Graph**, linking related events together.
5. Maps findings to **MITRE ATT&CK TTPs**.

---

## 2. Module Structure

```
src/correlation/
├── __init__.py                # Exports: TimelineBuilder, ThreatScorer
├── timeline_builder.py        # Chronological sorting and event merging
└── threat_scorer.py           # Rule-based heuristic risk evaluation & evidence graph generation
```

---

## 3. Core Components

### 3.1 `TimelineBuilder` Class

**File:** `src/correlation/timeline_builder.py`

Responsible for unifying disparate forensic artifacts into a single, time-ordered sequence of events. Handles disk artifacts, memory processes, network connections, etc.

### 3.2 `ThreatScorer` Class

**File:** `src/correlation/threat_scorer.py`

Evaluates findings against heuristic rules to identify anomalies, lateral movement indicators, and execution of malicious payloads. It assigns `finding_id`s, constructs relationships, and adds MITRE ATT&CK mappings.

#### 3.2.1 `evaluate_timeline(timeline: list) -> list`

Evaluates generic timeline events (e.g., Suspicious Prefetch). Adds basic MITRE mappings (`T1204` for malicious execution, `T1059` for suspicious paths).

#### 3.2.2 `evaluate_cross_module(...) -> tuple(list, list)`

This is the flagship analytic capability. It compares findings across modules to detect patterns invisible to single-purpose tools.

**Rule 8: Process-Network Correlation**
- A process with suspicious memory (RWX) AND outbound network connections = likely C2 implant.
- **MITRE TTPs:** T1071.001, T1055
- **Evidence Graph:** `CONTRIBUTES_TO` links from the memory and network findings to the new cross-module finding.

**Rule 9: Persistence-Memory Correlation**
- Registry persistence entry pointing to a process with RWX memory = active implant.
- **MITRE TTPs:** T1547.001, T1055

**Rule 10: DLL-Memory Correlation**
- Injected DLLs + RWX memory in the same process = confirmed code injection.
- **MITRE TTPs:** T1055.001, T1574.002

**Rule 11: Temporal Correlation**
- 3+ high-risk events detected across multiple modules in the same scan window = Coordinated Attack.
- **MITRE TTPs:** T1059, T1055, T1071
- **Evidence Graph:** `TEMPORAL_LINK` relationships between findings.

**Rule 12: LOLBin Chain Detection**
- Multiple Living-Off-The-Land binaries (e.g., `cmd.exe`, `powershell.exe`, `certutil.exe`) active simultaneously.
- **MITRE TTPs:** T1059.001, T1218

---

## 4. Evidence Graph & Data Schema

The `ThreatScorer` enforces strict JSON schema validation and emits relationship tuples that are digested by the `CaseManager`.

**Relationship Tuple Schema:**
```python
(source_finding_id, target_finding_id, relationship_type, confidence)
```

**Example Output Payload:**

```json
{
  "finding_id": "FND-A1B2C3D4",
  "timestamp": "2026-08-23T16:02:11Z",
  "source_module": "memory",
  "event_type": "CROSS_MODULE_THREAT",
  "description": "[CRITICAL CORRELATION] Process malware.exe (PID 1337) has BOTH suspicious memory regions AND outbound network connections - possible active C2 implant",
  "risk_score": 95,
  "mitre_attack_ttps": ["T1071.001", "T1055"]
}
```

---

## 5. Usage Example

```python
from src.correlation import ThreatScorer
from src.core import CaseManager

manager = CaseManager("CASE-123")
scorer = ThreatScorer()

# Run deep cross-module correlation
cross_threats, relationships = scorer.evaluate_cross_module(
    memory_findings=mem_findings,
    network_findings=net_findings,
    persistence_findings=pers_findings,
    dll_findings=dll_findings
)

# Store relationships in the Case Object (Evidence Graph)
for s_id, t_id, rel_type, conf in relationships:
    manager.add_relationship(s_id, t_id, rel_type, conf)
```

---

*Document version: 2.0 — September 2026*
