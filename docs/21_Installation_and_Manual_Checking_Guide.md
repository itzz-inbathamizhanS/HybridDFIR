# Hybrid Forensics Framework: Installation & Complete Manual Checking Guide

This document details how to install the Hybrid Forensics Framework and provides a step-by-step example plan for manually running every single module and command to ensure comprehensive coverage during an incident response engagement.

---

## 1. Installation Guide

The framework is designed to operate on live, air-gapped systems and prioritizes zero-dependency execution wherever possible.

### Prerequisites
- **Operating System:** Windows 10/11 or Windows Server 2016+
- **Privileges:** You **MUST** run the framework from an Administrator command prompt or PowerShell session to access protected memory regions.
- **Python:** Python 3.8+ installed on the system (or packaged as a portable runtime).

### Step-by-Step Setup
1. **Clone or Copy the Repository:**
   Move the `hybrid-forensics-framework` folder to the target machine via secure USB or authorized transfer.

2. **Set up a Virtual Environment (Recommended):**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install Core Requirements:**
   ```powershell
   pip install -r requirements.txt
   ```
   *Note: If operating air-gapped, you should download the `rich` library dependencies as wheels offline and install them via `pip install --no-index --find-links=.\offline_packages -r requirements.txt`.*

4. **Verify Administrator Access:**
   Ensure your shell says "Administrator" in the title bar.

---

## 2. Complete Manual Checking Guide (Execution Plan)

When responding to an incident, run the following commands sequentially to ensure all artifacts, memory regions, and network connections are audited.

> **Tip:** You can always view the full list of available commands and detailed descriptions by running:
> ```powershell
> python src/main.py --help
> ```

### Phase 1: Case Initialization
Before running scans, create a case file to ensure all findings are correlated, recorded, and saved immutably.

**Command 1: Create the Case**
```powershell
python src/main.py --create-case "Operation Shadow" --analyst "Admin" --desc "Investigation of initial access"
```
*(Copy the generated `CASE-ID` from the output, e.g., `CASE-20260910-C7EF57`)*

### Phase 2: Live Memory & Process Auditing
Extract artifacts from live system RAM.

**Command 2: Scan Process Lineage**
```powershell
python src/main.py --process-tree
```
*Purpose:* Maps parent-child processes. Flags anomalies like `cmd.exe` spawned from critical system services (`lsass.exe`, `wininit.exe`).

**Command 3: Scan Native RAM**
```powershell
python src/main.py --scan
```
*Purpose:* Uses `ctypes` and Win32 APIs to scan process memory for anomalous executable protection constants (e.g., `PAGE_EXECUTE_READWRITE`) indicating shellcode injection.

**Command 4: Inspect DLLs for Hollowing**
```powershell
python src/main.py --dllinspect
```
*Purpose:* Analyzes the PE headers of loaded DLLs across all running processes to detect side-loading and process hollowing techniques.

### Phase 3: Network & Connectivity Auditing
Identify live command-and-control (C2) connections.

**Command 5: Network Connection Intelligence**
```powershell
python src/main.py --network
```
*Purpose:* Uses `iphlpapi.dll` to dump all active TCP/UDP connections. Flags unencrypted traffic over suspicious ports or processes making raw socket connections.

### Phase 4: Disk & Persistence Auditing
Look for mechanisms attackers use to survive reboots.

**Command 6: Persistence Hunter**
```powershell
python src/main.py --persistence
```
*Purpose:* Scans the Windows Registry (Run keys, Services) for unauthorized auto-start entries and LOLBins (`powershell.exe -Enc`, `bitsadmin`, etc.).

**Command 7: Deep Artifact Analyzer**
```powershell
python src/main.py --scan-artifacts "C:\"
```
*Purpose:* Performs heuristic evaluation of Prefetch files (execution of malicious tools like `mimikatz.exe`) and Event Logs (cleared `Security.evtx`).

### Phase 5: Threat Intelligence Correlation
Bring in offline Threat Intel to find known bad actors.

**Command 8: Setup Indicators**
Create a file named `indicators.json` in the root directory (using STIX-like syntax):
```json
{
    "indicators": [
        { "type": "ipv4-addr", "value": "1.1.1.1" },
        { "type": "file:name", "value": "nc.exe" }
    ]
}
```

**Command 9: Offline IOC Engine**
```powershell
python src/main.py --scan-ioc indicators.json
```
*Purpose:* Cross-references the live system telemetry (current network IP addresses, running process names) against your custom indicator list.

### Phase 6: Unified Summary & Archiving
Finally, run the Unified Dashboard to merge all independent scans, compute cross-module correlations, and save a final threat score.

**Command 10: Run the Unified Dashboard**
```powershell
python src/main.py --dashboard --case-id "CASE-20260910-C7EF57"
```
*Purpose:* Generates the final executive summary. You can provide this output to management or external CIRT teams.

**Command 11: Verify Case Integrity**
```powershell
python src/main.py --verify-case "CASE-20260910-C7EF57"
```
*Purpose:* Verifies that no evidence or logs within the case have been tampered with post-collection.
