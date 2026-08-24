# System Architecture

> Hybrid Memory & Disk Forensics Framework — Architectural Overview

---

## 1. Design Philosophy

The framework is designed around three core principles:

| Principle | Description |
|---|---|
| **Air-Gapped Security** | All processing is strictly local. No network calls, no telemetry, no cloud dependencies. Sensitive forensic data never leaves the analyst's machine. |
| **Modular Pipeline** | Each forensic stage (intake → analysis → correlation → response) is an independent Python module with a well-defined interface. |
| **Zero-Binary Inspection** | The native RAM scanner uses only Win32 APIs via `ctypes` — no third-party kernel drivers, no `psutil`, nothing that would trigger driver-blocklist alerts on hardened endpoints. |

---

## 2. Project Directory Structure

```
hybrid-forensics-framework/
├── docs/                          # Architectural documentation (this folder)
│   ├── 00_system_architecture.md
│   ├── 01_evidence_intake.md
│   ├── 02_disk_analysis.md
│   ├── 03_memory_analysis.md
│   ├── 04_correlation_engine.md
│   ├── 05_action_response.md
│   └── 20_release_notes.md
├── output/                        # Generated reports and forensic captures
│   ├── <evidence_id>/             # Per-case JSON + HTML reports
│   └── native_ram_scan_*.json     # Standalone live scan results
├── src/
│   ├── capture/                   # Live RAM acquisition (Phase 1)
│   │   ├── native_ram.py          # Zero-binary driverless memory scanner
│   │   └── live_ram.py            # Forensic capture engine (scan + MiniDumps)
│   ├── config/                    # Global settings and data schemas
│   │   ├── settings.py            # Paths, formats, air-gap directives
│   │   ├── data_models.json       # JSON Schema definitions (Draft-07)
│   │   └── __init__.py            # Schema loader utility
│   ├── correlation/               # Threat scoring and timeline building
│   │   ├── timeline_builder.py    # Chronological event merger
│   │   └── threat_scorer.py       # Heuristic risk evaluation engine
│   ├── disk/                      # Disk artifact extraction
│   │   ├── fs_parser.py           # File system walker + MAC timestamps
│   │   └── artifact_extractor.py  # Registry hive + Prefetch extraction
│   ├── intake/                    # Evidence validation and cataloging
│   │   ├── ingest_image.py        # Intake orchestrator (EvidenceIntake)
│   │   └── validator.py           # Chunk-based MD5/SHA-256 hashing
│   ├── memory/                    # Offline memory image analysis
│   │   ├── process_scanner.py     # Volatility 3 process extraction
│   │   └── volatility_wrapper.py  # Subprocess wrapper for vol3 CLI
│   ├── response/                  # Report generation
│   │   └── report_generator.py    # JSON + self-contained HTML output
│   └── main.py                    # Interactive CLI orchestrator (REPL)
├── tests/                         # Automated test suite (pytest)
│   ├── test_intake.py
│   ├── test_disk.py
│   ├── test_memory.py
│   └── test_correlation.py
├── requirements.txt               # Python dependencies
├── LICENSE                        # MIT License
└── README.md                      # Project overview and usage guide
```

---

## 3. Pipeline Architecture

The framework processes forensic evidence through a sequential, five-stage pipeline. Each stage receives structured input and produces structured output conforming to the JSON schemas defined in `src/config/data_models.json`.

```
┌─────────────────┐
│  Evidence Image  │   .raw / .dd / .vmem / .dmp
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  1. INTAKE       │   EvidenceIntake → validates, hashes, catalogs
│  src/intake/     │   Output: EvidenceMetadata dict
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌─────────┐
│ 2.DISK │ │3.MEMORY │   Runs in parallel based on --type flag
│src/disk│ │src/memory│   Disk: ArtifactExtractor → DiskArtifact[]
└───┬────┘ └────┬────┘   Memory: ProcessScanner → MemoryProcess[]
    │           │
    └─────┬─────┘
          ▼
┌─────────────────┐
│ 4. CORRELATION   │   TimelineBuilder + ThreatScorer
│ src/correlation/ │   Output: timeline[] + CorrelatedEvent[]
└────────┬────────┘
         ▼
┌─────────────────┐
│ 5. RESPONSE      │   ReportGenerator
│ src/response/    │   Output: forensic_report.json + forensic_report.html
└─────────────────┘
```

### Pipeline Entry Points

The framework supports three modes of operation via `src/main.py`:

| Mode | Command | Description |
|---|---|---|
| **Interactive REPL** | `python src/main.py` | Launches the `❯` prompt with `/scan`, `/capture`, `/analyze` commands |
| **CLI Flags** | `python src/main.py --image <path> --type <type>` | Directly runs the full pipeline on an existing image |
| **Standalone Scanner** | `python src/capture/native_ram.py` | Runs only the native RAM scanner for quick triage |

---

## 4. Data Flow & Schema Contracts

All inter-module communication follows strict JSON schemas defined in [`src/config/data_models.json`](../src/config/data_models.json). There are four core data models:

| Schema | Producer | Consumer | Description |
|---|---|---|---|
| `EvidenceMetadata` | `intake/ingest_image.py` | `correlation/`, `response/` | File identity, hashes, intake timestamp |
| `DiskArtifact` | `disk/artifact_extractor.py` | `correlation/timeline_builder.py` | Registry hives, Prefetch files with timestamps |
| `MemoryProcess` | `memory/process_scanner.py` | `correlation/threat_scorer.py` | Running processes extracted from memory dumps |
| `CorrelatedEvent` | `correlation/threat_scorer.py`, `capture/native_ram.py` | `response/report_generator.py` | Unified threat events with risk scores (0–100) |

---

## 5. Configuration System

Global configuration is centralized in [`src/config/settings.py`](../src/config/settings.py):

```python
# Air-Gapped Security Directive
ALLOW_NETWORK_ACCESS = False
OFFLINE_MODE = True

# Directory Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = BASE_DIR / "output"
TEMP_DIR   = BASE_DIR / "temp"

# Intake Rules
HASH_CHUNK_SIZE = 65536  # 64 KB
SUPPORTED_DISK_FORMATS   = [".raw", ".dd", ".img", ".vhd", ".vmdk"]
SUPPORTED_MEMORY_FORMATS = [".raw", ".vmem", ".dmp", ".sav"]
```

The `OUTPUT_DIR` and `TEMP_DIR` directories are created automatically at import time. All report outputs, scan results, and forensic captures are written under `output/`.

---

## 6. Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| **Language** | Python 3.8+ | Core runtime |
| **CLI Framework** | `rich`, `questionary`, `prompt_toolkit` | Interactive REPL, tables, panels, progress bars |
| **Win32 Integration** | `ctypes` (stdlib) | Native RAM scanning — zero external dependencies |
| **Memory Forensics** | Volatility 3 (optional) | Offline memory image analysis |
| **Hashing** | `hashlib` (stdlib) | MD5 + SHA-256 for chain-of-custody |
| **Testing** | `pytest` | Unit and integration tests |

---

## 7. Security Architecture

### Air-Gap Enforcement

The `ALLOW_NETWORK_ACCESS = False` and `OFFLINE_MODE = True` flags in `settings.py` serve as documented policy directives. The codebase contains zero `requests`, `urllib`, or socket-based calls — every module operates exclusively on local file I/O and Win32 system calls.

### Chain of Custody

Evidence integrity is maintained through:

1. **Dual hashing** — Every evidence file is hashed with both MD5 and SHA-256 at intake time using chunk-based reading (64 KB chunks to handle multi-GB images).
2. **Immutable evidence IDs** — Each case receives a unique `evidence_id` derived from the image type and the first 8 characters of the MD5 hash (e.g., `memory_a5f5479a`).
3. **UTC timestamps** — All timestamps are recorded in ISO 8601 UTC format for timezone-independent reproducibility.

### Privilege Model

- **`/scan` and `/capture` commands** require Administrator privileges (validated via `shell32.IsUserAnAdmin()`).
- **`/analyze` command** operates on offline images and does not require elevation.
- Privilege checks fail gracefully with a rich error panel — no silent failures.

---

*Document version: 1.0 — August 2026*
