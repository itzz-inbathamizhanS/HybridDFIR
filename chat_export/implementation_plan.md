# Hybrid Forensics Framework — Complete Codebase Analysis & SIH Implementation Plan

> **Goal:** Exhaustive analysis of every file (excluding `src/capture/`) — identify all bugs, errors, gaps, missing features, and propose a hackathon-winning upgrade path.

---

## Complete File Inventory (38 Files Analyzed)

| # | File | Lines | Status |
|---|------|-------|--------|
| 1 | [README.md](file:///a:/hybrid-forensics-framework/README.md) | 129 | Needs update |
| 2 | [LICENSE](file:///a:/hybrid-forensics-framework/LICENSE) | 22 | OK |
| 3 | [requirements.txt](file:///a:/hybrid-forensics-framework/requirements.txt) | 3 | INCOMPLETE |
| 4 | [.gitignore](file:///a:/hybrid-forensics-framework/.gitignore) | 6 | Needs additions |
| 5 | [src/\_\_init\_\_.py](file:///a:/hybrid-forensics-framework/src/__init__.py) | 0 | OK |
| 6 | [src/main.py](file:///a:/hybrid-forensics-framework/src/main.py) | 232 | BUGS FOUND |
| 7 | [src/config/\_\_init\_\_.py](file:///a:/hybrid-forensics-framework/src/config/__init__.py) | 12 | OK |
| 8 | [src/config/settings.py](file:///a:/hybrid-forensics-framework/src/config/settings.py) | 20 | Missing settings |
| 9 | [src/config/schemas.py](file:///a:/hybrid-forensics-framework/src/config/schemas.py) | 41 | Incomplete |
| 10 | [src/config/data_models.json](file:///a:/hybrid-forensics-framework/src/config/data_models.json) | 58 | Schema drift |
| 11 | [src/intake/\_\_init\_\_.py](file:///a:/hybrid-forensics-framework/src/intake/__init__.py) | 4 | OK |
| 12 | [src/intake/ingest_image.py](file:///a:/hybrid-forensics-framework/src/intake/ingest_image.py) | 51 | BUGS FOUND |
| 13 | [src/intake/validator.py](file:///a:/hybrid-forensics-framework/src/intake/validator.py) | 34 | Enhancement needed |
| 14 | [src/disk/\_\_init\_\_.py](file:///a:/hybrid-forensics-framework/src/disk/__init__.py) | 4 | OK |
| 15 | [src/disk/fs_parser.py](file:///a:/hybrid-forensics-framework/src/disk/fs_parser.py) | 42 | Enhancement needed |
| 16 | [src/disk/artifact_extractor.py](file:///a:/hybrid-forensics-framework/src/disk/artifact_extractor.py) | 64 | MISSING ARTIFACTS |
| 17 | [src/memory/\_\_init\_\_.py](file:///a:/hybrid-forensics-framework/src/memory/__init__.py) | 4 | OK |
| 18 | [src/memory/volatility_wrapper.py](file:///a:/hybrid-forensics-framework/src/memory/volatility_wrapper.py) | 37 | Security concern |
| 19 | [src/memory/process_scanner.py](file:///a:/hybrid-forensics-framework/src/memory/process_scanner.py) | 40 | Dead code present |
| 20 | [src/correlation/\_\_init\_\_.py](file:///a:/hybrid-forensics-framework/src/correlation/__init__.py) | 4 | OK |
| 21 | [src/correlation/timeline_builder.py](file:///a:/hybrid-forensics-framework/src/correlation/timeline_builder.py) | 50 | MISSING risk_score |
| 22 | [src/correlation/threat_scorer.py](file:///a:/hybrid-forensics-framework/src/correlation/threat_scorer.py) | 55 | Shallow rules |
| 23 | [src/response/\_\_init\_\_.py](file:///a:/hybrid-forensics-framework/src/response/__init__.py) | 3 | OK |
| 24 | [src/response/report_generator.py](file:///a:/hybrid-forensics-framework/src/response/report_generator.py) | 80 | BAREBONES HTML |
| 25 | [tests/test_intake.py](file:///a:/hybrid-forensics-framework/tests/test_intake.py) | 23 | Low coverage |
| 26 | [tests/test_disk.py](file:///a:/hybrid-forensics-framework/tests/test_disk.py) | 81 | Good |
| 27 | [tests/test_memory.py](file:///a:/hybrid-forensics-framework/tests/test_memory.py) | 22 | Low coverage |
| 28 | [tests/test_correlation.py](file:///a:/hybrid-forensics-framework/tests/test_correlation.py) | 34 | Low coverage |
| 29 | [tests/test_pipeline_integration.py](file:///a:/hybrid-forensics-framework/tests/test_pipeline_integration.py) | 60 | Good |
| 30-38 | docs/ (9 files) | ~900+ | Needs sync |

**Test Status: All 11 tests PASS (verified)**

---

## CRITICAL BUGS AND ERRORS

### Bug 1 — `EvidenceIntake` Does NOT Validate File Format

**File:** [ingest_image.py:19](file:///a:/hybrid-forensics-framework/src/intake/ingest_image.py#L19)

```python
if self.image_type not in ['disk', 'memory']:
    raise ValueError("Invalid image type. Must be 'disk' or 'memory'.")
```

**Problem:** The intake accepts `image_type` but **never validates the file extension** against `SUPPORTED_DISK_FORMATS` or `SUPPORTED_MEMORY_FORMATS` from `settings.py`. A user could pass `memdump.xlsx` and the framework would blindly hash and process it.

**Fix:** Add format validation:
```python
from src.config.settings import SUPPORTED_DISK_FORMATS, SUPPORTED_MEMORY_FORMATS

ext = os.path.splitext(self.file_path)[1].lower()
valid_formats = SUPPORTED_DISK_FORMATS if self.image_type == 'disk' else SUPPORTED_MEMORY_FORMATS
if ext not in valid_formats:
    raise ValueError(f"Unsupported {self.image_type} format: '{ext}'. Supported: {valid_formats}")
```

---

### Bug 2 — `EvidenceIntake` Accepts `"hybrid"` via CLI but Rejects It in Code

**File:** [main.py:81](file:///a:/hybrid-forensics-framework/src/main.py#L81) vs [ingest_image.py:19](file:///a:/hybrid-forensics-framework/src/intake/ingest_image.py#L19)

**Problem:** The CLI (`main.py`) supports `--type hybrid` and the REPL accepts `hybrid` for `/analyze`, but `EvidenceIntake.__init__()` only allows `'disk'` or `'memory'`. When `run_pipeline()` is called with `image_type="hybrid"`, it passes `"hybrid"` to `EvidenceIntake` which **raises a ValueError** and crashes.

```python
# main.py line 53 — passes "hybrid" directly
intake = EvidenceIntake(image_path, image_type)  # CRASH if hybrid
```

**Fix:** Either normalize `"hybrid"` to `"memory"` in the intake (since it is primarily a memory image with disk mount), or update `EvidenceIntake` to accept `"hybrid"`.

---

### Bug 3 — `TimelineBuilder` Does NOT Produce `risk_score` Field

**File:** [timeline_builder.py:14-20](file:///a:/hybrid-forensics-framework/src/correlation/timeline_builder.py#L14-L20)

**Problem:** Timeline events produced by `TimelineBuilder.ingest_disk_artifacts()` and `ingest_memory_processes()` do **NOT include a `risk_score` field**, but the `CorrelatedEvent` schema in `data_models.json` **requires** `risk_score`. The `ThreatScorer` only adds `risk_score` when it flags something — but the timeline events passed to the HTML report can contain events without `risk_score`, causing potential `KeyError` crashes in `report_generator.py` if these events are included in the threats list.

**Fix:** Add a default `risk_score: 0` to all timeline events.

---

### Bug 4 — `report_generator.py` Crashes If `source_module` Is None

**File:** [report_generator.py:34](file:///a:/hybrid-forensics-framework/src/response/report_generator.py#L34)

```python
<td>{threat.get('source_module').upper()}</td>
```

**Problem:** `.get('source_module')` returns `None` if the key is missing. Calling `.upper()` on `None` causes `AttributeError: 'NoneType' object has no attribute 'upper'`. Should use `.get('source_module', 'UNKNOWN').upper()`.

---

### Bug 5 — `datetime.datetime.utcnow()` Deprecation Warning

**File:** [native_ram.py:401](file:///a:/hybrid-forensics-framework/src/capture/native_ram.py#L401)

```python
"scan_timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
```

**Problem:** `datetime.utcnow()` is **deprecated** in Python 3.12+. On Python 3.14 (your version), this generates a `DeprecationWarning`. Should use `datetime.datetime.now(datetime.timezone.utc)` instead. *(Note: not touching capture, but flagging for awareness)*

---

### Bug 6 — `_human_size` Function Duplicated Across Two Files

**Files:** [native_ram.py:620](file:///a:/hybrid-forensics-framework/src/capture/native_ram.py#L620) and [live_ram.py:434](file:///a:/hybrid-forensics-framework/src/capture/live_ram.py#L434)

**Problem:** Identical `_human_size()` utility function copy-pasted in two capture files. Not a crash-bug but violates DRY and creates maintenance risk.

---

## SIGNIFICANT GAPS AND WEAKNESSES

### Gap 1 — `requirements.txt` is Incomplete

**File:** [requirements.txt](file:///a:/hybrid-forensics-framework/requirements.txt)

Current contents:
```
rich>=13.0
questionary>=2.0
prompt_toolkit>=3.0
```

**Missing:**
- `pytest` — required to run tests
- `volatility3` — mentioned in README as prerequisite but never listed
- No version pinning — risks broken installs

**Fix:**
```
rich>=13.0
questionary>=2.0
prompt_toolkit>=3.0
pytest>=7.0
```

---

### Gap 2 — Disk Artifact Extractor Only Parses 2 Artifact Types

**File:** [artifact_extractor.py](file:///a:/hybrid-forensics-framework/src/disk/artifact_extractor.py)

Currently extracts only:
1. SYSTEM Registry Hive
2. Prefetch Files

**Missing critical Windows forensic artifacts:**
- **SAM Registry Hive** — User accounts, password hashes
- **SOFTWARE Registry Hive** — Installed programs, autoruns
- **SECURITY Registry Hive** — Security policies, audit logs
- **NTUSER.DAT** — Per-user settings, recent files, USB history
- **Windows Event Logs** (`.evtx`) — Security, System, Application logs
- **$MFT** — Master File Table for full NTFS timeline
- **USN Journal** — File change tracking
- **Amcache.hve** — Application execution evidence
- **SRUM Database** — App resource usage history
- **Browser artifacts** — History, downloads, cookies

> [!IMPORTANT]
> For SIH, judges will question why a "forensics framework" only parses 2 artifact types. Adding at least SAM, SOFTWARE, NTUSER.DAT, and Event Logs would significantly strengthen the project.

---

### Gap 3 — `ThreatScorer` Has Only 2 Heuristic Rules

**File:** [threat_scorer.py](file:///a:/hybrid-forensics-framework/src/correlation/threat_scorer.py)

Only has:
1. Suspicious Prefetch executables
2. Suspicious memory process names + paths

**Missing critical detection rules:**
- **Parent-Child process anomalies** (e.g., `svchost.exe` spawned by `cmd.exe` instead of `services.exe`)
- **DLL injection indicators**
- **Timestomping detection** (created_time > modified_time)
- **Registry persistence mechanisms** (Run/RunOnce keys)
- **Lateral movement indicators** (PsExec, WMI, SMB)
- **Encoding/obfuscation indicators** (base64 in process cmdline)
- **YARA rule integration** for pattern matching

> [!WARNING]
> The 4-item `suspicious_executables` list is trivially bypassed by renaming the binary. Real forensics tools use behavioral heuristics, not name-based matching.

---

### Gap 4 — HTML Report is Extremely Basic

**File:** [report_generator.py](file:///a:/hybrid-forensics-framework/src/response/report_generator.py)

**Problems:**
- No timeline visualization (just a threat table)
- No evidence metadata display (hashes, file details)
- No risk score summary charts
- No process tree visualization
- No export/print functionality
- No JavaScript interactivity (sorting, filtering)
- No dark mode
- Very basic CSS styling

> [!IMPORTANT]
> For SIH demo, the HTML report is your **primary visual deliverable** that judges will see. It must look professional and interactive.

---

### Gap 5 — No JSON Schema Validation at Runtime

**Files:** [data_models.json](file:///a:/hybrid-forensics-framework/src/config/data_models.json), [schemas.py](file:///a:/hybrid-forensics-framework/src/config/schemas.py)

**Problem:** You define JSON schemas AND Python TypedDicts but **never actually validate data against them**. There is no `jsonschema.validate()` call anywhere in the codebase. The `load_schemas()` function in `config/__init__.py` loads the schemas but nobody calls it.

The `schemas.py` TypedDicts are also never used — they are defined but no function type hints reference them.

---

### Gap 6 — No Logging Framework

**Problem:** The entire codebase (except `native_ram.py`) uses bare `print()` statements. There is no structured logging with the `logging` module. This makes debugging, audit trails, and log collection impossible.

---

### Gap 7 — No Error Recovery / Graceful Degradation in Pipeline

**File:** [main.py:47-124](file:///a:/hybrid-forensics-framework/src/main.py#L47-L124)

**Problem:** `run_pipeline()` has no try/except blocks. If any stage fails (e.g., corrupt evidence file, permission error during disk parsing), the entire pipeline crashes with an unhandled exception. A forensic tool must be resilient.

---

### Gap 8 — `.gitignore` Missing Important Patterns

**File:** [.gitignore](file:///a:/hybrid-forensics-framework/.gitignore)

**Missing patterns:**
```
*.raw
*.dmp
*.vmem
*.dd
.env
*.egg-info/
dist/
build/
.vscode/
.idea/
```

Evidence files (`.raw`, `.dmp`) should NEVER be committed to git.

---

### Gap 9 — No `__init__.py` in `src/capture/`

**Problem:** The `src/capture/` directory has no `__init__.py` file. Imports work only because of `sys.path` manipulation in `main.py`. This is fragile and non-standard.

---

### Gap 10 — `ProcessScanner.check_for_injected_code()` Returns Raw Data

**File:** [process_scanner.py:34-40](file:///a:/hybrid-forensics-framework/src/memory/process_scanner.py#L34-L40)

**Problem:** `check_for_injected_code()` returns raw Volatility output without mapping it to the `CorrelatedEvent` schema. This method is also **never called** anywhere in the pipeline — it is dead code.

---

## PROPOSED SIH-WINNING IMPROVEMENTS

> [!IMPORTANT]
> The following improvements are ordered by **judge impact** — highest impact first. Each maps to a specific SIH judging criterion.

### Phase A — Critical Bug Fixes (Must Do)

| # | Fix | File(s) | Effort |
|---|-----|---------|--------|
| A1 | Fix `hybrid` type crash in `EvidenceIntake` | `ingest_image.py`, `main.py` | 30 min |
| A2 | Add file format validation in intake | `ingest_image.py` | 15 min |
| A3 | Fix `NoneType.upper()` crash in report HTML | `report_generator.py` | 5 min |
| A4 | Add default `risk_score` in timeline events | `timeline_builder.py` | 10 min |
| A5 | Add error handling in `run_pipeline()` | `main.py` | 30 min |

---

### Phase B — Strengthen Core (High Impact)

| # | Feature | File(s) | Effort |
|---|---------|---------|--------|
| B1 | Add SAM, SOFTWARE, SECURITY, NTUSER.DAT registry hive extraction | `artifact_extractor.py` | 2 hrs |
| B2 | Add Windows Event Log (`.evtx`) detection and metadata extraction | New: `disk/evtx_parser.py` | 2 hrs |
| B3 | Add Amcache.hve parsing (application execution evidence) | `artifact_extractor.py` | 1 hr |
| B4 | Expand `ThreatScorer` with 6+ new heuristic rules (parent-child anomaly, timestomping, registry persistence, etc.) | `threat_scorer.py` | 3 hrs |
| B5 | Add structured `logging` throughout all modules | All source files | 1.5 hrs |
| B6 | Add runtime JSON Schema validation using `jsonschema` library | `config/__init__.py`, pipeline stages | 1 hr |
| B7 | Update `requirements.txt` with full dependency list | `requirements.txt` | 10 min |

---

### Phase C — Demo-Winning UI (Highest Visual Impact)

| # | Feature | File(s) | Effort |
|---|---------|---------|--------|
| C1 | **Complete HTML report overhaul** — dark theme, glassmorphism, interactive timeline chart, risk pie chart, process tree view, evidence metadata cards, export to PDF | `report_generator.py` | 4 hrs |
| C2 | Add timeline visualization using embedded Chart.js (CDN-free, inline JS) | `report_generator.py` | 2 hrs |
| C3 | Add MITRE ATT&CK mapping to threat labels | `threat_scorer.py`, `report_generator.py` | 2 hrs |

---

### Phase D — Test and Documentation Polish

| # | Task | File(s) | Effort |
|---|------|---------|--------|
| D1 | Add tests for hybrid mode, file validation, edge cases | `tests/` | 2 hrs |
| D2 | Add tests for new registry hive extractors | `tests/test_disk.py` | 1 hr |
| D3 | Add tests for expanded threat scorer rules | `tests/test_correlation.py` | 1 hr |
| D4 | Update README with new features, architecture diagram | `README.md` | 1 hr |
| D5 | Update `.gitignore` with complete patterns | `.gitignore` | 5 min |

---

## SIH-Specific Recommendations

### What Judges Look For vs What You Have

| SIH Criteria | Current State | After Fix |
|---|---|---|
| **Innovation** | Good — zero-binary driverless scanning is novel | Excellent — add MITRE ATT&CK mapping |
| **Technical Complexity** | Good — ctypes Win32 integration | Excellent — add schema validation, expanded heuristics |
| **Feasibility** | Pipeline crashes on `hybrid` mode | Robust error handling |
| **Impact/Scalability** | Only 2 disk artifact types | 7+ artifact types, event logs |
| **User Experience** | Barebones HTML report | Professional interactive dashboard |
| **Completeness** | Dead code, missing validations | Full pipeline, all code paths tested |

### Priority Order for Limited Time

If you have **24 hours**, do: A1 then A2 then A3 then A4 then A5 then C1 then B4 then B1

If you have **48 hours**, add: B2 then B3 then B5 then C2 then C3 then D1

If you have **72+ hours**, add: B6 then D2 then D3 then D4 then D5

---

## Open Questions

> [!IMPORTANT]
> 1. **How much time do you have before SIH?** This determines which phases to prioritize.
> 2. **Will you be doing a live demo?** If yes, Phase C (HTML report) is the highest priority because judges see it.
> 3. **Do you want MITRE ATT&CK TTP mapping?** This adds huge credibility — mapping threat labels to official MITRE IDs (e.g., `RWX_SHELLCODE_INJECTION` maps to T1055.012 Process Hollowing).
> 4. **Should the HTML report be fully offline (no CDN)?** Currently it is — but adding Chart.js inline would need around 200KB of embedded JavaScript. Should I inline it or skip charts?
> 5. **Do you want me to proceed with Phase A (critical bug fixes) first?**

---

## Verification Plan

### Automated Tests
```bash
pytest tests/ -v
```
- All existing 11 tests must continue to pass
- New tests will cover expanded artifact extractors, threat scorer rules, and hybrid mode

### Manual Verification
- Run `/scan` on a live Windows machine with admin privileges
- Run `/analyze memory sample_mem.raw` to test offline pipeline
- Open generated `forensic_report.html` in browser to verify visual quality
- Verify JSON report validates against `data_models.json` schema
