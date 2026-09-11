# 17. Installation and Quick Start Guide

This guide provides step-by-step instructions for deploying and running the Hybrid Forensics Framework on a target Windows machine.

## Prerequisites

Before running the framework, ensure the target system meets the following requirements:
1. **Operating System:** Windows 10 or Windows 11 (64-bit).
2. **Python Environment:** Python 3.8+ installed. 
   - *Note: Since this is designed as a zero-dependency forensics tool, you do not need to install complex C++ build tools or external parsers. It relies purely on the Python standard library and `ctypes`.*
3. **Privileges:** You **MUST** run the framework from an elevated command prompt (Administrator). Live memory inspection requires the `SeDebugPrivilege` to open handles to system processes.

---

## Installation

Because the framework is designed to be air-gapped and portable for incident response teams, the installation footprint is minimal.

1. **Clone or Copy the Repository:**
   Transfer the `hybrid-forensics-framework` folder to the target machine via USB or secure transfer.

2. **Setup Virtual Environment (Optional but Recommended):**
   ```powershell
   cd hybrid-forensics-framework
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install Requirements:**
   The only external dependency is the `rich` library for rendering the UI.
   ```powershell
   pip install -r requirements.txt
   ```

---

## Quick Start (Running the Tool)

The framework is invoked through the `src/main.py` entry point. 

### 1. Launching the Unified Dashboard
To run all 4 scanning engines (Memory, Network, Persistence, DLLs) simultaneously and pass their results through the Correlation Engine:

```powershell
python src\main.py --dashboard
```

### 2. Targeting Specific Modules
If you only need to investigate a specific forensic artifact, you can run individual engines:

**Live Memory Scan (Process Injection & Hollowing):**
```powershell
python src\main.py --scan
```

**Network Intelligence (Live Connections):**
```powershell
python src\main.py --network
```

**Registry Persistence Hunter:**
```powershell
python src\main.py --persistence
```

**DLL Inspection:**
```powershell
python src\main.py --dllinspect
```

### 3. Understanding the Output
Every scan generates a detailed, time-stamped JSON report in the `output/` directory (e.g., `output/unified_dashboard_1789069047.json`). These JSON files contain raw forensic evidence and risk scores that can be ingested by external SIEMs (like Splunk or ElasticSearch).
