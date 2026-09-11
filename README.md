# Hybrid Memory & Disk Forensics Framework

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Build](https://img.shields.io/badge/build-passing-brightgreen)

An air-gapped, local digital forensics framework designed to perform advanced correlation between live memory artifacts, active network connections, process lineage, and persistent registry configurations.

Built entirely around a **100% Native Python & Win32 API (`ctypes`) architecture**, this framework bypasses third-party driver blocklists (e.g., no WinPMEM or Volatility requirements) and executes seamlessly on hardened enterprise endpoints.

---

## Core Features & Capabilities

* **Zero-Binary Live Memory Inspection**: Scans live RAM for fileless malware, reflective DLL injection, and process hollowing using native Windows APIs (VirtualQueryEx, Toolhelp32Snapshot).
* **Process Lineage Mapping**: Builds parent-child process trees to identify masquerading and suspicious execution chains.
* **DLL Hollowing Detection**: Parses internal PE structures and measures Shannon Entropy to uncover unbacked and packed modules.
* **Network C2 Auditing**: Correlates outbound connections to running processes via IP Helper APIs (`iphlpapi.dll`).
* **Persistent Threat Hunting**: Native registry parsing (`winreg`) to hunt for Image File Execution Options (IFEO) hijacking, AppInit_DLLs, and suspicious Run keys.
* **Cross-Module Evidence Graph**: Unified `CaseManager` correlates findings across Memory, Network, and Persistence to detect complex attack chains (Rules 1-12).
* **Action Response Dashboards**: Automatically exports heavily typed JSON payloads (`CASE_EXPORT_*.json`) and offline, self-contained interactive HTML dashboards with visual Evidence Graphs.
* **Air-Gapped & Secure**: Zero external network calls. Cryptographically hashed chain-of-custody audit logs ensure forensic integrity.

---

## Documentation

New to the project or looking to understand the core concepts? Start here:

### Core Reading
- **[Project Overview](docs/project_overview.md):** A comprehensive summary of the problem statement, HybridDFIR's automated pipeline, system architecture, and real-world use cases.
- **[Core Forensics Concepts](docs/forensics_concepts.md):** An easy-to-understand guide explaining the attack vectors HybridDFIR hunts for, including Registry Persistence, DLL Injection/Hollowing, and Network Command & Control (C2).
- **[Commands & Usage Guide](docs/commands_guide.md):** A complete reference manual for all available interactive REPL and direct CLI commands with examples.

### Complete Documentation Reference
- [00 System Architecture](docs/00_system_architecture.md)
- [01 Architecture Overview](docs/01_Architecture_Overview.md)
- [02 Evidence Intake](docs/02_Evidence_Intake.md)
- [03 Disk Analysis](docs/03_Disk_Analysis.md)
- [04 Memory Analysis](docs/04_Memory_Analysis.md)
- [05 Correlation Engine](docs/05_Correlation_Engine.md)
- [06 Action Response](docs/06_Action_Response.md)
- [07 Module Deep Dive](docs/07_Module_Deep_Dive.md)
- [08 Threat Scoring Methodology](docs/08_Threat_Scoring_Methodology.md)
- [09 Disk and Intake Engine](docs/09_Disk_and_Intake_Engine.md)
- [10 Reporting and UI Engine](docs/10_Reporting_and_UI_Engine.md)
- [11 Data Models and Configuration](docs/11_Data_Models_and_Configuration.md)
- [12 Command Line Interface](docs/12_Command_Line_Interface.md)
- [13 Malware Analysis Case Study](docs/13_Malware_Analysis_Case_Study.md)
- [17 Installation and QuickStart](docs/17_Installation_and_QuickStart.md)
- [18 Troubleshooting and FAQ](docs/18_Troubleshooting_and_FAQ.md)
- [19 Developer Integration Guide](docs/19_Developer_Integration_Guide.md)
- [20 Release Notes](docs/20_release_notes.md)
- [21 Installation and Manual Checking Guide](docs/21_Installation_and_Manual_Checking_Guide.md)
- [30 Final Architecture Review](docs/30_Final_Architecture_Review.md)

---

## System Architecture

The framework relies on a centralized `CaseManager` state engine that processes data through a multi-stage pipeline:

```text
hybrid-forensics-framework/
├── docs/                      # Architectural documentation and methodology
├── output/                    # Isolated Case containers (JSON + HTML reports)
├── src/
│   ├── capture/               # Native Live RAM scanning & DLL inspection
│   ├── config/                # Global configuration & JSON schemas
│   ├── core/                  # CaseManager, Audit Logs, and Evidence Graph mapping
│   ├── correlation/           # ThreatScorer (Rules 1-12) & MITRE ATT&CK mapping
│   ├── intelligence/          # Local IOC ingestion engine
│   ├── network/               # Active connection auditing
│   ├── persistence/           # Registry & Autoruns hunting
│   └── response/              # HTML Dashboard and JSON Export generation
├── tests/                     # Pytest suite
└── main.py                    # Interactive CLI Orchestrator
```

## Installation & Setup

**Prerequisites**
*   Python 3.8+ (Windows environments only)
*   Git

**Installation**

```bash
git clone https://github.com/itzz-inbathamizhanS/HybridDFIR.git
cd HybridDFIR
python -m venv venv
```

**Activate the virtual environment:**

Windows (CMD):
```cmd
venv\Scripts\activate
```

Windows (PowerShell):
```powershell
.\venv\Scripts\Activate.ps1
```

**Install dependencies:**
```bash
pip install -r requirements.txt
```

## Usage & CLI Operations

The framework is executed via the `src/main.py` orchestrator.
**Note: Native RAM scanning requires Administrator privileges.**

```bash
# Launch the interactive CLI
python src/main.py
```

### Direct CLI Commands

Bypass the interactive menu and run commands directly for automation scripts:

```bash
# Run a full cross-module forensic sweep and generate a report
python src/main.py --sweep

# Launch the offline interactive dashboard for the last sweep
python src/main.py --dashboard

# Re-verify the cryptographic chain-of-custody for a specific case
python src/main.py --verify-case CASE-20260910-A1B2C3

# Run the built-in self-test simulator
python src/main.py --self-test
```

### Reviewing Reports
Outputs are automatically saved in isolated case folders:
`output/CASE-YYYYMMDD-XXXXXX/`
*   `CASE_EXPORT_<timestamp>.json`: Full structured dataset for SIEM ingestion.
*   `forensic_report.html`: Self-contained interactive dashboard (requires no internet connection).

## Cross-Module Threat Correlation

The correlation engine utilizes 12 specific heuristic rules, ranging from isolated anomalies to complex cross-module attack patterns:
*   **Rule 8 (Process + Network):** Detects highly suspicious memory regions executing outbound connections (C2 implants).
*   **Rule 9 (Persistence + Memory):** Detects persistent registry entries pointing to active, injected processes in memory.
*   **Rule 10 (DLL + Memory):** Unbacked injected DLLs matched with RWX memory regions.
*   **Rule 12 (LOLBin Chaining):** Detects simultaneous execution of Living-Off-The-Land binaries (`certutil.exe` -> `powershell.exe`).

## Testing Suite

Run the automated test suite to ensure all internal modules and JSON schemas are functioning correctly:

```bash
pytest tests/ -v
```
Set-Content requirements.txt "rich==13.7.0`nquestionary==2.0.1`npytest==7.4.4`njsonschema==4.21.1"
---
*Built for modern Windows Endpoint Security Analysis.*
**Disclaimer:** This tool is designed for educational, research, and legitimate incident response purposes. Always ensure you have explicit authorization before analyzing systems or digital evidence.

## Open-Source & Licensing

This project is released under the **MIT License**.

### Offline Operation
The framework is designed to operate completely offline in air-gapped environments. The HTML/CSS dashboards are fully self-contained and require no external CDNs or online telemetry.

## License Check
To verify the open-source compliance of the environment, run:
```powershell
python src/main.py --license-check
```
