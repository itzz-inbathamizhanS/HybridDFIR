# Hybrid Memory & Disk Forensics Framework

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Build](https://img.shields.io/badge/build-passing-brightgreen)

An open-source, air-gapped Command Line Interface (CLI) tool designed for secure, local-only digital forensics analysis. 

This framework securely ingests forensic images, independently parses disk artifacts and memory dumps, and utilizes a heuristic Correlation Engine to merge findings into a unified timeline, scoring potential threats without relying on external APIs or network calls.

---

## 🌟 Core Features

* **Evidence Intake:** Secure chunk-based MD5 and SHA256 hashing for chain-of-custody validation.
* **Disk Analysis:** Extracts file system metadata, parses Windows SYSTEM Registry hives, and analyzes Prefetch files to identify executed applications.
* **Memory Analysis:** Local air-gapped integration with Volatility 3 to extract active processes and hunt for injected code. Includes graceful fallback handling if Volatility is missing.
* **Correlation Engine:** Merges disk and memory artifacts into a single chronological timeline and assigns risk scores using heuristic rules.
* **Action Response:** Automatically generates self-contained JSON data outputs and human-readable HTML dashboards for offline viewing.
* **Zero External Dependencies:** Built entirely with local libraries to ensure no sensitive forensic data ever leaves your machine.

---

## 📂 Project Structure

```text
hybrid-forensics-framework/
├── docs/                 # System architecture and documentation
├── src/                  # Core Application Code
│   ├── main.py           # CLI Entry point & orchestrator
│   ├── config/           # Enforces local-only execution & JSON schemas
│   ├── intake/           # Evidence hashing and validation
│   ├── disk/             # File system parsing & artifact extraction
│   ├── memory/           # Process scanning & Volatility wrapper
│   ├── correlation/      # Timeline builder and heuristic threat scorer
│   └── response/         # JSON and HTML report generation
├── tests/                # Automated Pytest suite (Master Revision Loop)
└── output/               # Generated reports and logs (Git-ignored)


🛠️ Step-by-Step Installation & Setup
Prerequisites
Python 3.8+

Git

Volatility 3 (Required for analyzing real memory images. Install via pip install volatility3)

Installation
Clone the repository:

Bash
git clone [https://github.com/vedhan7/hybrid-forensics-framework.git](https://github.com/vedhan7/hybrid-forensics-framework.git)
cd hybrid-forensics-framework
Create a virtual environment:

Windows (CMD/PowerShell):

DOS
python -m venv venv
Linux/macOS:

Bash
python3 -m venv venv
Activate the virtual environment:

Windows (CMD):

DOS
venv\Scripts\activate
Windows (PowerShell):

PowerShell
.\venv\Scripts\Activate.ps1
Linux/macOS:

Bash
source venv/bin/activate
Install dependencies:

Bash
pip install pytest
💻 Running the Framework
The framework is executed entirely via the command line orchestrator (src/main.py).

1. Analyzing a Memory Dump
Bash
python src/main.py --image "C:\path\to\evidence\memdump.raw" --type memory
(To test without a real memory dump, you can create a dummy file: echo "test" > sample.raw and run the command against it).

2. Analyzing a Mounted Disk Image
Note: Disk images must be mounted locally before running analysis.

Bash
python src/main.py --image "C:\path\to\evidence\disk.dd" --type disk --mount "D:\"
3. Reviewing Reports
Outputs are automatically saved in the generated output/<EVIDENCE_ID>/ folder inside your project directory:

forensic_report.json: Full structured dataset.

forensic_report.html: Self-contained interactive dashboard viewable in any web browser.

🧪 Testing Suite (Master Revision Loop)
Run the automated test suite using pytest to ensure all data schemas, intake hashing, and volatility parsers function as expected without requiring actual forensic images:

Bash
pytest tests/ -v
⚠️ Disclaimer
This tool is designed for educational, research, and legitimate incident response purposes. Always ensure you have explicit authorization before analyzing systems or digital evidence.
