# HybridDFIR — Comprehensive Error Report

> [!CAUTION]
> **8 test failures**, **3 runtime crashes**, and **22 static analysis warnings** found across the codebase.

---

## 1. Runtime Crashes (Will crash the REPL / CLI)

These are errors that **will** cause a `Traceback` when the user hits a specific code path.

### 1.1 `NameError: 'tree_findings' is not defined`
| File | Line | Severity |
|------|------|----------|
| [main.py](file:///d:/HybridDFIR/src/main.py#L251) | 251 | 🔴 CRITICAL |

**Status:** ✅ Fixed in previous edit (initialized `tree_findings = []` and `ioc_findings = []`)

The `run_unified_dashboard()` summary table references `tree_findings` and `ioc_findings`, but neither variable was ever assigned. These modules (process tree, IOC engine) are not yet wired into the dashboard scan loop — the stats table rows reference them prematurely.

---

### 1.2 `TypeError: run_unified_dashboard() missing 1 required positional argument: 'case_id'`
| File | Line | Severity |
|------|------|----------|
| [main.py](file:///d:/HybridDFIR/src/main.py#L769) | 769 | 🔴 CRITICAL |

**Status:** ✅ Fixed in previous edit (auto-creates an ad-hoc case)

The REPL's `/dashboard` handler called `run_unified_dashboard(critical_only=...)` without a `case_id`, but the function signature requires one: `def run_unified_dashboard(case_id: str, critical_only: bool = False)`.

---

### 1.3 `'str' object has no attribute 'get'` in `ingest_memory_processes`
| File | Line | Severity |
|------|------|----------|
| [timeline_builder.py](file:///d:/HybridDFIR/src/correlation/timeline_builder.py#L35-L43) | 35–43 | 🟡 MEDIUM |

In `run_pipeline()`, `memory_processes` is assigned the **entire return dict** from `scanner.extract_running_processes()` (which is `{"status": "SUCCESS", "processes": [...]}`) instead of just the list of processes. When this dict is passed to `builder.ingest_memory_processes(memory_processes, ...)`, the method iterates and calls `.get()` on each item — but the items are strings (dict keys), not dicts.

**Root cause in [main.py L403-404](file:///d:/HybridDFIR/src/main.py#L403-L404):**
```python
memory_processes = scanner.extract_running_processes()  # Returns dict, not list!
console.print(f"... Extracted {len(memory_processes)} processes")  # len() = 3 (dict keys)
```
Should be:
```python
result = scanner.extract_running_processes()
memory_processes = result.get("processes", [])
```

---

## 2. Test Failures (8 of 23 tests FAIL)

### 2.1 `test_intake.py` — 6 failures

All 6 failures stem from a **schema mismatch** between what `EvidenceIntake.process_evidence()` returns and what the tests expect.

#### Root Cause: Return value structure changed

`process_evidence()` returns a **wrapper dict**:
```python
{"status": "SUCCESS", "metadata": { ... actual data ... }}
```

But the tests directly access fields like `result["file_name"]`, `result["evidence_id"]`, etc., expecting the **metadata dict** itself.

Additionally, the metadata fields themselves changed names:

| Tests expect | Actual field in `process_evidence()` |
|---|---|
| `result["file_name"]` | `result["metadata"]["original_filename"]` |
| `result["image_type"]` | `result["metadata"]["evidence_type"]` |
| `result["hashes"]` | `result["metadata"]["additional_hashes"]` + `result["metadata"]["SHA-256"]` |
| `result["evidence_id"]` | `result["metadata"]["evidence_id"]` (prefix `EVID-MEMORY-` not `memory_`) |
| `result["size_bytes"]` | `result["metadata"]["file_size"]` |
| `result["intake_timestamp_utc"]` | Not present in new schema |
| `result["file_path"]` | `result["metadata"]["source_metadata"]["file_path"]` |

**Specific test failures:**

| Test | Error | Reason |
|------|-------|--------|
| `test_evidence_intake_success` | `KeyError: 'file_name'` | Tests access `result["file_name"]` but it's nested under `result["metadata"]["original_filename"]` |
| `test_evidence_intake_invalid_type` | `DID NOT RAISE ValueError` | `process_evidence()` returns `{"status": "ERROR"}` instead of raising `ValueError` |
| `test_evidence_intake_hybrid_type` | `KeyError: 'image_type'` | Same wrapper nesting issue |
| `test_evidence_intake_memory_type` | `KeyError: 'image_type'` | Same wrapper nesting issue |
| `test_evidence_intake_file_not_found` | `DID NOT RAISE FileNotFoundError` | `process_evidence()` returns `{"status": "ERROR"}` instead of raising |
| `test_evidence_intake_metadata_fields` | `AssertionError: Missing required field` | Field names changed, nesting changed |

> [!IMPORTANT]
> **Decision needed:** Either update the tests to match the new return structure, or update `EvidenceIntake` to raise exceptions and return flat metadata like the tests expect.

---

### 2.2 `test_memory.py::test_extract_running_processes` — 1 failure

| Error | `AssertionError: assert 3 == 1` |
|---|---|

`scanner.extract_running_processes()` returns a dict `{"status": ..., "reason": ..., "processes": [...]}`. The test does:
```python
processes = scanner.extract_running_processes()
assert len(processes) == 1  # len() of the dict = 3 keys!
```
Should be `processes = scanner.extract_running_processes()["processes"]`.

---

### 2.3 `test_pipeline_integration.py::test_pipeline_integration` — 1 failure

| Error | `KeyError: 'evidence_metadata'` |
|---|---|

The test expects the report data passed to `generate_json_report()` to have keys `evidence_metadata`, `timeline`, and `threats` — but the pipeline now uses the **Case Object** schema with `findings`, `metadata`, etc. The entire report structure changed but the test wasn't updated.

---

## 3. Logic Bugs (Won't crash, but produce wrong results)

### 3.1 `run_pipeline` passes full dict instead of process list
| File | Lines | Severity |
|------|-------|----------|
| [main.py](file:///d:/HybridDFIR/src/main.py#L403-L424) | 403–424 | 🟡 MEDIUM |

As described in §1.3, `memory_processes` holds the full response dict. This means:
- `len(memory_processes)` reports `3` (dict keys) instead of the actual process count
- `builder.ingest_memory_processes(memory_processes, ...)` crashes with `'str' object has no attribute 'get'`
- The error is caught and swallowed by the `except Exception` handler at line 431

### 3.2 `EvidenceIntake.__init__` doesn't validate type
| File | Line | Severity |
|------|-------|----------|
| [ingest_image.py](file:///d:/HybridDFIR/src/intake/ingest_image.py#L17-L22) | 17–22 | 🟡 MEDIUM |

The constructor accepts any `image_type` string without validation. Validation only happens inside `process_evidence()`, but it returns `{"status": "ERROR"}` instead of raising `ValueError`. Tests expect the constructor or `process_evidence()` to raise.

### 3.3 `process_evidence()` returns error dict instead of raising
| File | Lines | Severity |
|------|-------|----------|
| [ingest_image.py](file:///d:/HybridDFIR/src/intake/ingest_image.py#L31-L35) | 31–35 | 🟡 MEDIUM |

On invalid type or missing file, `process_evidence()` returns `{"status": "ERROR", "reason": "..."}`. The caller in `run_pipeline()` (main.py L362) never checks for this — it proceeds to use `intake_metadata` as if it's the metadata dict, leading to downstream `KeyError`s.

### 3.4 `intake_metadata` used inconsistently in `run_pipeline`
| File | Line | Severity |
|------|-------|----------|
| [main.py](file:///d:/HybridDFIR/src/main.py#L362-L380) | 362–380 | 🟡 MEDIUM |

`intake_metadata = intake.process_evidence()` returns `{"status": "SUCCESS", "metadata": {...}}`. Then later:
- Line 371: `intake_metadata.get("evidence_id")` → gets `None` (it's nested)
- Line 374: `intake_metadata.get("size_bytes")` → gets `None`
- Line 378: `intake_metadata.get("hashes", {})` → gets `{}`
- Line 424: `intake_metadata.get("intake_timestamp_utc")` → gets `None`
- Line 469: `case_data["metadata"] = intake_metadata` → stores the wrapper, not metadata

The code displays "N/A" / "0.0 GB" for all evidence metadata — functionally broken but doesn't crash.

---

## 4. Static Analysis Warnings (pyflakes)

### Unused Imports
| File | Import | Line |
|------|--------|------|
| [main.py](file:///d:/HybridDFIR/src/main.py#L32) | `src.core.EvidenceGraph` | 32 |
| [live_ram.py](file:///d:/HybridDFIR/src/capture/live_ram.py#L35) | `rich.progress.TimeElapsedColumn` | 35 |
| [audit_log.py](file:///d:/HybridDFIR/src/core/audit_log.py#L3) | `pathlib.Path` | 3 |
| [case_manager.py](file:///d:/HybridDFIR/src/core/case_manager.py#L4-L5) | `os`, `pathlib.Path` | 4–5 |
| [evidence_graph.py](file:///d:/HybridDFIR/src/core/evidence_graph.py#L2) | `pathlib.Path` | 2 |
| [artifact_analyzer.py](file:///d:/HybridDFIR/src/disk/artifact_analyzer.py#L1-L2) | `os`, `datetime` | 1–2 |
| [ingest_image.py](file:///d:/HybridDFIR/src/intake/ingest_image.py#L5) | `SUPPORTED_DISK_FORMATS`, `SUPPORTED_MEMORY_FORMATS` | 5 |
| [process_tree.py](file:///d:/HybridDFIR/src/memory/process_tree.py#L9) | `datetime` | 9 |

### Redundant/Shadowed Imports
| File | Issue | Line |
|------|-------|------|
| [main.py](file:///d:/HybridDFIR/src/main.py#L68) | Redefinition of `datetime` (imported at L7 and again at L68) | 68 |

### Unused Variables
| File | Variable | Line |
|------|----------|------|
| [main.py](file:///d:/HybridDFIR/src/main.py#L301) | `report_path` assigned but never used (report is saved via `ReportGenerator`) | 301 |
| [main.py](file:///d:/HybridDFIR/src/main.py#L657) | `threats` in `run_self_test()` — evaluated but result discarded | 657 |
| [volatility_wrapper.py](file:///d:/HybridDFIR/src/memory/volatility_wrapper.py#L47) | `e` in `except json.JSONDecodeError as e` — never used | 47 |

### f-strings Without Placeholders
| File | Line |
|------|------|
| [main.py](file:///d:/HybridDFIR/src/main.py#L278) | `f"  System Threat Score  : "` |
| [main.py](file:///d:/HybridDFIR/src/main.py#L280) | `f"  System Status        : "` |
| [live_ram.py](file:///d:/HybridDFIR/src/capture/live_ram.py#L235) | Various |
| [threat_scorer.py](file:///d:/HybridDFIR/src/correlation/threat_scorer.py#L215) | `f"Windows Event Log artifact detected"` |

---

## 5. Deprecation Warnings

All uses of `datetime.datetime.utcnow()` are deprecated in Python 3.12+ and scheduled for removal:

| File | Lines |
|------|-------|
| [ingest_image.py](file:///d:/HybridDFIR/src/intake/ingest_image.py#L62-L63) | 62, 63 |
| [case_manager.py](file:///d:/HybridDFIR/src/core/case_manager.py#L18-L32) | 18, 26, 32 |
| [timeline_builder.py](file:///d:/HybridDFIR/src/correlation/timeline_builder.py#L73-L93) | 73, 93 |
| [threat_scorer.py](file:///d:/HybridDFIR/src/correlation/threat_scorer.py#L310-L424) | Multiple |

**Fix:** Replace with `datetime.datetime.now(datetime.UTC)`.

---

## Summary

| Category | Count | Status |
|----------|-------|--------|
| 🔴 Runtime crashes | 3 | 2 fixed, 1 remaining |
| 🔴 Test failures | 8 of 23 | All unfixed |
| 🟡 Logic bugs | 4 | All unfixed |
| ⚪ Static warnings | 22 | All unfixed |
| ⚪ Deprecation warnings | 8+ calls | All unfixed |

### Priority Fix Order
1. **`run_pipeline` memory_processes dict vs list bug** — causes silent data loss (§1.3 / §3.1)
2. **`EvidenceIntake` return structure vs test expectations** — fixes 7 of 8 test failures (§2.1 / §2.2)
3. **`test_pipeline_integration` report schema mismatch** — fixes last test failure (§2.3)
4. **`intake_metadata` wrapper nesting** — fixes evidence display in pipeline (§3.4)
5. **Deprecation warnings** — future-proofing
6. **Static analysis cleanup** — code hygiene
