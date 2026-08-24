# Action Response Module

> Module: `src/response/` — Automated Report Generation

---

## 1. Overview

The Action Response module is the final stage of the forensic pipeline. It is responsible for taking all collected metadata, timelines, and correlated threat events, and packaging them into offline-accessible reports. 

Adhering to the framework's air-gapped philosophy, this module writes all reports strictly to the local file system.

---

## 2. Module Structure

```
src/response/
├── __init__.py                # Exports: ReportGenerator
└── report_generator.py        # JSON and HTML report generation engine
```

---

## 3. Core Components

### 3.1 `ReportGenerator` Class

**File:** `src/response/report_generator.py`

#### Constructor

```python
ReportGenerator(case_id: str)
```

| Parameter | Type | Description |
|---|---|---|
| `case_id` | `str` | The unique `evidence_id` generated during intake (e.g., `memory_a5f5479a`) |

Upon instantiation, the generator automatically creates an isolated report directory for the case inside the framework's configured `OUTPUT_DIR` (default: `output/<case_id>/`).

#### `generate_json_report(report_data: dict) → str`

Saves the complete, raw analysis output as a structured JSON file.

- **File created:** `forensic_report.json`
- **Contents:** The exact `report_data` dictionary passed in, serialized with 2-space indentation.
- **Returns:** Absolute path to the generated JSON file.

This file is intended for ingestion into upstream SIEMs, log aggregators, or further automated processing pipelines.

#### `generate_html_report(report_data: dict) → str`

Generates a self-contained, human-readable HTML dashboard.

- **File created:** `forensic_report.html`
- **Contents:** A single-file HTML document with embedded CSS.
- **Returns:** Absolute path to the generated HTML file.

**HTML Features & Logic:**
- Fully offline — no external CDNs, web fonts, or remote JS libraries are referenced.
- Iterates over the `report_data.get("threats", [])` list.
- Automatically color-codes threats based on their `risk_score`:
  - **Score ≥ 70:** Colored Red (`#ff4d4d`) — High-risk indicator.
  - **Score < 70:** Colored Orange (`#ffa500`) — Medium-risk indicator.

---

## 4. Pipeline Integration

The `ReportGenerator` is invoked at the very end of `src/main.py::run_pipeline()`:

```python
# Create the generator instance for this specific case
report_gen = ReportGenerator(intake_metadata["evidence_id"])

# Assemble the final payload
final_payload = {
    "evidence_metadata": intake_metadata,
    "timeline": timeline,
    "threats": threats
}

# Generate both report formats
json_path = report_gen.generate_json_report(final_payload)
html_path = report_gen.generate_html_report(final_payload)
```

---

## 5. Output Directory Structure

The framework keeps output strictly organized by Case ID to prevent cross-contamination between different evidence analysis runs.

```text
hybrid-forensics-framework/
└── output/
    └── memory_a5f5479a/                   # Directory named via Evidence ID
        ├── forensic_report.json           # Machine-readable raw data
        └── forensic_report.html           # Human-readable dashboard
```

---

*Document version: 1.0 — August 2026*
