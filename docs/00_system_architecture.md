# System Architecture

> Hybrid Memory & Disk Forensics Framework — Final Architectural Overview

---

## 1. Design Philosophy

The framework is designed around three core principles:

| Principle | Description |
|---|---|
| **Air-Gapped Security** | All processing is strictly local. No network calls, no telemetry, no cloud dependencies. Sensitive forensic data never leaves the analyst's machine. |
| **Native Execution** | Built entirely on Python 3.8+ and native Win32 APIs (`ctypes`). Zero third-party C-extensions, kernel drivers, or heavy dependencies (e.g., `psutil` or `volatility3` are fully deprecated). |
| **Cross-Module Correlation** | Individual forensic modules (Memory, Network, Persistence, DLLs) do not operate in silos. Findings are correlated to build a comprehensive **Evidence Graph** revealing complex attack chains. |

---

## 2. Project Directory Structure

```
hybrid-forensics-framework/
├── docs/                          # Architectural documentation (this folder)
├── output/                        # Generated reports and forensic captures
│   └── CASE-<date>-<hash>/        # Immutable per-case storage
│       ├── CASE_EXPORT_<date>.json # Final Case Object payload
│       └── forensic_report.html   # Standalone HTML dashboard
├── src/
│   ├── capture/                   # Live RAM acquisition & Native API inspection
│   │   ├── native_ram.py          # Zero-binary memory scanner (RWX hunting)
│   │   └── dll_inspector.py       # PE parsing for Module Hollowing detection
│   ├── config/                    # Global settings and schemas
│   │   ├── settings.py            # Paths, formats, air-gap directives
│   │   └── data_models.json       # JSON Schema definitions (Draft-07)
│   ├── core/                      # Central State & Case Management
│   │   ├── case_manager.py        # Immutable Case Object state engine
│   │   └── evidence_graph.py      # Relationship mappings (e.g. Process -> Network)
│   ├── correlation/               # Threat scoring and timeline building
│   │   ├── timeline_builder.py    # Chronological event merger
│   │   └── threat_scorer.py       # Heuristic evaluation & MITRE mapping (Rules 1-12)
│   ├── intelligence/              # Offline Threat Intel
│   │   └── ioc_engine.py          # Validates live data against local JSON IOCs
│   ├── network/                   # Live Connectivity Auditing
│   │   └── connection_scanner.py  # Uses iphlpapi.dll for active C2 detection
│   ├── persistence/               # Registry & Autorun Hunting
│   │   └── registry_scanner.py    # Native winreg parsing for Run/Services keys
│   ├── response/                  # Report generation
│   │   └── report_generator.py    # JSON + self-contained HTML output
│   └── main.py                    # Main orchestrator & CLI entrypoint
├── tests/                         # Automated test suite (pytest)
├── requirements.txt               # Minimal Python dependencies
└── README.md                      # Project overview and usage guide
```

---

## 3. Pipeline Architecture

The framework processes forensic evidence through a sequential pipeline, governed by the `CaseManager`.

```
┌─────────────────┐
│ 1. CASE INIT     │   CaseManager creates an immutable Case Object.
│ src/core/        │   Output: CASE-YYYYMMDD-XXXXXX
└────────┬────────┘
         │
    ┌────┴───────────────────────────┬───────────────────────────┐
    ▼                                ▼                           ▼
┌──────────────┐             ┌────────────────┐            ┌───────────────┐
│ 2. MEMORY    │             │ 3. NETWORK     │            │ 4. DISK       │
│ native_ram.py│             │ connection_... │            │ registry_...  │
│ dll_inspect..│             │                │            │               │
└──────────────┘             └────────────────┘            └───────────────┘
    │                                │                           │
    └────────────────────────────────┼───────────────────────────┘
                                     ▼
                      ┌────────────────────────────┐
                      │ 5. CORRELATION ENGINE      │  ThreatScorer
                      │ src/correlation/           │  Applies Rules 1-12.
                      └──────────────┬─────────────┘  Builds EvidenceGraph.
                                     ▼
                      ┌────────────────────────────┐
                      │ 6. REPORT GENERATOR        │  ReportGenerator
                      │ src/response/              │  Outputs CASE_EXPORT JSON
                      └────────────────────────────┘  and offline HTML.
```

---

## 4. Data Flow & Schema Contracts

All inter-module communication is stored within the central `CaseManager` state engine, which strictly adheres to JSON schemas:

| Schema | Role | Description |
|---|---|---|
| `CaseObject` | The core state. | Contains case metadata, analyst info, and all nested findings. |
| `AuditLog` | Chain of Custody. | An append-only list of every action taken by the framework. |
| `Finding` | Individual alerts. | Unique `FND-*` ID, timestamps, description, and MITRE TTPs. |
| `Relationship` | The Evidence Graph. | Links two Finding IDs together (e.g. `TEMPORAL_LINK`, `CONTRIBUTES_TO`). |

---

## 5. Security Architecture

### Air-Gap Enforcement
The `ALLOW_NETWORK_ACCESS = False` and `OFFLINE_MODE = True` flags in `settings.py` serve as documented policy directives. The codebase contains zero external API calls to VirusTotal or cloud telemetry.

### Immutable Case Objects & Chain of Custody
1. **Append-Only Logging** — Every command execution is logged to the `CaseObject`'s audit log.
2. **Cryptographic Chaining** — The `CaseManager` implements SHA-256 hash chaining of audit events (`--verify-case`).
3. **No External CDNs** — The generated HTML report embeds all CSS (Tailwind) and fonts internally.

### Privilege Model
The framework interacts deeply with protected OS structures via `ctypes`. It **MUST** be run as Administrator. The CLI automatically verifies privileges at startup.

---

*Document version: Final — September 2026*
