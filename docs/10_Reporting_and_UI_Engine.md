# Reporting and UI Engine Specifications

This document outlines how the Hybrid Forensics Framework transforms raw Python dictionaries into a stunning, responsive, and standalone HTML Dashboard.

## `src/response/report_generator.py`

This module contains the `ReportGenerator` class, which takes the final output from the `ThreatScorer` and produces both JSON and HTML artifacts.

### 1. JSON Report Generation (`generate_json_report()`)
- **Output:** `output/report_<evidence_id>_<timestamp>.json`
- **Structure:**
  - `report_metadata`: Time generated, framework version, evidence ID.
  - `evidence_info`: The hashes and sizes from the Intake module.
  - `threat_summary`: Total number of threats found.
  - `timeline`: The complete chronological sequence of benign and malicious events.
  - `correlated_threats`: The filtered list of high-risk events, sorted by risk score descending.

### 2. HTML Dashboard Generation (`generate_html_report()`)
- **Output:** `output/dashboard_<evidence_id>_<timestamp>.html`
- **Design Philosophy:** Air-gapped compatible. All CSS styles and JavaScript logic are embedded directly into the HTML string. No external CDN calls are made. It works perfectly on an isolated, offline forensic workstation.

#### A. Executive Summary Section
- Displays the `Evidence ID`, `Timestamp`, and `SHA-256` hash.
- Renders a colored pill indicating the overall system status:
  - **Critical (Red)**: If any threat score >= 70.
  - **Warning (Yellow)**: If max threat score is between 40 and 69.
  - **Clean (Green)**: If no threats detected.

#### B. Threat Breakdown Cards
- Dynamically iterates over the `threats` array.
- Generates a styled CSS card for every finding.
- **Card Elements:**
  - **Header**: Risk Score (colored red/yellow based on severity) and MITRE TTPs as badges.
  - **Body**: The detailed description (e.g., `[CONFIRMED INJECTION] svchost.exe...`).
  - **Footer**: The source module (Memory, Network, Persistence) and the exact UTC timestamp.

#### C. System Timeline Section
- A responsive, vertical CSS timeline.
- Iterates over the `timeline` array (both benign and malicious events).
- Events are rendered as dots on the line, with threat events highlighted in red and disk/benign events in blue.

#### D. The "Unified Dashboard" Terminal UI (`src/main.py`)
In addition to the HTML report, the framework uses the `Rich` Python library to render a beautiful terminal interface when running `python src/main.py --dashboard`.

- **Overall Gauge**: Calculates a weighted score (60% max risk + 40% top 10 average) to give a 0-100 gauge.
- **Top 10 Processes**: Extracts process names from all findings across all 4 modules and ranks them by their highest observed risk score.
- **Module Statistics**: A summary table showing exactly how many findings were detected by the Memory, Network, Persistence, and DLL modules.
