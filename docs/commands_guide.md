# HybridDFIR: Commands & Usage Guide

HybridDFIR can be operated in two distinct modes:
1. **Interactive REPL Shell:** A continuous, live dashboard for active incident response and live triage.
2. **Direct CLI Mode:** Standalone commands for automation, scripting, and CI/CD pipelines.

---

## 1. Interactive Shell Commands (REPL)

To launch the interactive shell, simply run the tool with no arguments:
```bash
python src/main.py
```
This drops you into the `(HybridDFIR)>` prompt. The following commands are available:

### 🌟 Unified Dashboard
- `/dashboard`
  - **What it does:** Runs **all** live modules simultaneously (Memory, Network, Persistence, DLL Inspect), cross-correlates the findings, and generates a massive visual threat summary in the terminal.
  - **Example:** `/dashboard` (Shows all findings)
  - **Example:** `/dashboard --critical` (Filters the dashboard to only show CRITICAL severity threats)

### 🧠 Live Memory & Modules
- `/scan`
  - **What it does:** Performs a native scan of live RAM using Windows APIs, looking for RWX memory segments, injected shellcode, and process hollowing.
  - **Example:** `/scan` (Shows all flagged memory regions)
  - **Example:** `/scan --critical` (Shows only critical memory anomalies)

- `/network`
  - **What it does:** Audits the Windows routing table and active TCP/UDP sockets, correlating them back to the specific Process IDs that opened them.
  - **Example:** `/network` (Shows all connections)
  - **Example:** `/network --threats` (Highlights connections from non-standard processes like `calc.exe`)

- `/persistence`
  - **What it does:** Scans the Windows Registry (Run keys, AppInit_DLLs, IFEOs) for malware attempting to survive system reboots.
  - **Example:** `/persistence` (Shows all persistence mechanisms)
  - **Example:** `/persistence --threats` (Shows only highly suspicious keys)

- `/dllinspect`
  - **What it does:** Uncovers unbacked and packed modules hiding inside legitimate processes by parsing internal PE structures.
  - **Example:** `/dllinspect`

### 🕵️ Forensic Capture & Offline Analysis
- `/capture`
  - **What it does:** Performs a deep forensic capture of the live system. It dumps the process memory of highly suspicious processes (MiniDumps) for offline analysis.
  - **Example:** `/capture` (Native memory dumping)
  - **Example:** `/capture --driver` (Attempts to use the WinPMEM kernel driver for a full physical RAM capture)

- `/analyze <type> <path> [mount_point]`
  - **What it does:** Analyzes an already captured offline image (e.g., from a thumb drive).
  - **Example:** `/analyze memory evidence/dump.raw`
  - **Example:** `/analyze disk evidence/drive.E01 E:\mount`

### ⚙️ General Commands
- `/clear`: Clears the terminal screen.
- `/help`: Displays the help menu.
- `/exit`: Exits the framework securely.

---

## 2. Direct CLI Automation Commands

These commands allow you to bypass the interactive shell and run HybridDFIR directly from a script, PowerShell, or CI/CD runner. 

> **Note:** Native RAM scanning requires Administrator privileges.

### 🚀 Execution Modes
```bash
# Run the Unified Threat Dashboard and automatically generate the HTML/JSON offline reports
python src/main.py --dashboard --case-id CASE-123456

# Analyze live process lineage, building a parent-child tree to find masquerading processes
python src/main.py --process-tree

# Scan the system against a local JSON file of known bad IPs and Hashes
python src/main.py --scan-ioc "C:\path\to\threat_intel.json"

# Perform deep analysis of disk artifacts (Registry, Prefetch) on an offline mounted drive
python src/main.py --scan-artifacts "E:\mounted_evidence"
```

### 🔬 Individual Live Scanners
```bash
# [Module 1] Run live RAM inspection
python src/main.py --scan

# [Module 2] Run network connection scanner
python src/main.py --network

# [Module 3] Run registry persistence hunter
python src/main.py --persistence

# [Module 4] Run DLL injection detector
python src/main.py --dllinspect
```

### 📁 Case Management
If you are running the `--dashboard` command or want to manage cases via CLI:
```bash
# Create a new secure case directory
python src/main.py --create-case "Ransomware_Investigation" --analyst "Alice" --desc "Server-01"

# View the metadata of a specific case
python src/main.py --case-info CASE-123456

# Cryptographically verify the integrity of a case (ensures no logs were tampered with)
python src/main.py --verify-case CASE-123456
```

### 🩺 Diagnostics & Health
```bash
# Verify environment compatibility, admin privileges, and native module access
python src/main.py --doctor

# Run the automated end-to-end framework test (CI/CD pipeline simulation)
python src/main.py --self-test

# Audit and display the open-source license compliance report
python src/main.py --license-check
```
