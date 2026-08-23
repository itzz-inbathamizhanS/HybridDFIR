# Hybrid Memory & Disk Forensics Framework

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Build](https://img.shields.io/badge/build-passing-brightgreen)

An air-gapped, local digital forensics framework designed to perform advanced correlation between physical memory artifacts and disk-based artifacts. 

Phase 1 of the framework focuses on **zero-binary, driverless live RAM and process memory inspection** using native Win32 APIs via Python's `ctypes`, bypassing third-party driver blocks and detecting fileless malware, process hollowing, and shellcode injection directly in live physical memory.

---

## 🌟 Core Features & Key Capabilities

* **Zero-Binary Driverless Inspection**: Live RAM scanning without loading vulnerable or blocklisted kernel drivers (e.g., winpmem).
* **JIT-Aware Memory Whitelisting**: Intelligently suppresses false positives from known JIT compilers (V8, .NET CLR) and AV products.
* **Automated Heuristics**: Detects suspicious memory regions (`PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_WRITECOPY`, large private executables).
* **Evidence Intake:** Secure chunk-based MD5 and SHA256 hashing for chain-of-custody validation.
* **Disk Analysis:** Extracts file system metadata, parses Windows SYSTEM Registry hives, and analyzes Prefetch files.
* **Correlation Engine:** Merges disk and memory artifacts into a single chronological timeline and assigns risk scores using heuristic rules.
* **Action Response:** Automatically generates self-contained JSON data outputs and human-readable HTML dashboards for offline viewing.
* **Zero External Dependencies:** Built entirely with local libraries to ensure no sensitive forensic data ever leaves your machine.

---

## 📂 System Architecture & Project Structure

The framework is built using a highly modular pipeline approach:

```text
hybrid-forensics-framework/
├── docs/                      # Architectural documentation and guides
├── output/                    # Generated JSON and HTML reports
├── src/
│   ├── capture/               # Phase 1: Native Live RAM scanning (Win32 APIs)
│   │   ├── native_ram.py      # Core zero-binary memory walking & heuristics
│   │   └── live_ram.py        # Volatility-based acquisition (fallback)
│   ├── config/                # Global configuration & JSON schemas
│   ├── correlation/           # Threat scoring and timeline building
│   ├── disk/                  # Disk artifact extraction & parsing
│   ├── intake/                # Evidence validation and hashing
│   ├── memory/                # Process scanning and Volatility wrappers
│   └── response/              # HTML/JSON report generation
├── tests/                     # Unit and integration tests
├── requirements.txt           # Python dependencies (rich, questionary)
└── main.py                    # Interactive CLI Orchestrator
```

## 🛠️ Step-by-Step Installation & Setup

**Prerequisites**
*   Python 3.8+
*   Git
*   Volatility 3 (Required for analyzing real memory images. Install via `pip install volatility3`)

**Installation**

```bash
git clone https://github.com/vedhan7/hybrid-forensics-framework.git
cd hybrid-forensics-framework
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

Linux/macOS:
```bash
source venv/bin/activate
```

**Install dependencies:**
```bash
pip install -r requirements.txt
```

## 💻 Usage & Modes of Operation

The framework is executed entirely via the command line orchestrator (`src/main.py`).

**Note: Native RAM scanning requires Administrator privileges.**

```bash
python src/main.py
```

### Supported Modes

1. **Live Capture & Analyze**: Captures the current system RAM (using available methods) and runs the full analysis pipeline.
2. **Analyze Existing Evidence**: Parses an offline memory or disk image.
   * *Example offline dump analysis:* `python src/main.py --image "C:\path\to\evidence\memdump.raw" --type memory`
3. **Native Live RAM Scan (Phase 1)**: Runs the custom zero-binary memory scanner. Inspects all running processes for injection artifacts and surfaces critical threats while suppressing benign JIT noise.

### Reviewing Reports
Outputs are automatically saved in the generated `output/<EVIDENCE_ID>/` folder inside your project directory:
*   `forensic_report.json`: Full structured dataset.
*   `forensic_report.html`: Self-contained interactive dashboard viewable in any web browser.

## 🕵️ Threat Heuristics (Phase 1.1)

The Native RAM Scanner uses several heuristics to detect anomalies:
*   **`RWX_SHELLCODE_INJECTION` (Risk 90)**: Private memory regions with `PAGE_EXECUTE_READWRITE`.
*   **`RWX_WRITECOPY_SUSPICIOUS` (Risk 80)**: Image memory regions with `PAGE_EXECUTE_WRITECOPY`.
*   **`LARGE_PRIVATE_EXECUTABLE` (Risk 60)**: `PAGE_EXECUTE_READ` allocations over 1MB without backing files (indicative of hollowing).
*   **`RWX_GUARD_STAGED_PAYLOAD` (Risk 75)**: Executable pages marked with `PAGE_GUARD`.

*Note: Known JIT engines and AV tools are safely whitelisted to a Risk Score of 10 to reduce CLI noise, while preserving visibility in the final JSON report.*

## 🧪 Testing Suite (Master Revision Loop)

Run the automated test suite using `pytest` to ensure all data schemas, intake hashing, and parsers function as expected:

```bash
pytest tests/ -v
```

---
*Built for modern Windows Endpoint Security Analysis.*
⚠️ **Disclaimer:** This tool is designed for educational, research, and legitimate incident response purposes. Always ensure you have explicit authorization before analyzing systems or digital evidence.
