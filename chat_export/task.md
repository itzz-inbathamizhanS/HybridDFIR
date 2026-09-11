# SIH Implementation Tasks

## Phase A — Critical Bug Fixes
- `[x]` A1: Fix `hybrid` type crash in `EvidenceIntake`
- `[x]` A2: Add file format validation in intake
- `[x]` A3: Fix `NoneType.upper()` crash in report HTML
- `[x]` A4: Add default `risk_score` in timeline events
- `[x]` A5: Add error handling in `run_pipeline()`

## Phase B — Strengthen Core
- `[x]` B1: Add SAM, SOFTWARE, SECURITY, NTUSER.DAT registry hive extraction
- `[x]` B2: Add Windows Event Log (.evtx) detection
- `[x]` B3: Add Amcache.hve parsing
- `[x]` B4: Expand ThreatScorer with 6+ new heuristic rules
- `[x]` B5: Add structured logging throughout all modules
- `[x]` B6: Add runtime JSON Schema validation
- `[x]` B7: Update requirements.txt

## Phase C — Demo-Winning UI
- `[x]` C1: Complete HTML report overhaul
- `[x]` C2: Add timeline visualization
- `[x]` C3: Add MITRE ATT&CK mapping

## Phase D — Test & Documentation Polish
- `[x]` D1: Add tests for hybrid mode, file validation, edge cases
- `[x]` D2: Add tests for new registry hive extractors
- `[x]` D3: Add tests for expanded threat scorer rules
- `[x]` D4: Update README
- `[x]` D5: Update .gitignore
