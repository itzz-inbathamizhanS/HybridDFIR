# Threat Scoring Methodology

This document provides a highly detailed, line-by-line breakdown of the heuristic rules used by the `ThreatScorer` (`src/correlation/threat_scorer.py`) and the individual scanning modules to calculate risk scores.

Risk scores are capped at **100** for any single event.

## Individual Module Heuristics

### Memory Scanner (`src/capture/native_ram.py`)
*Line reference: ~Line 362-380*

- **RWX Shellcode Injection** (Score: **90**): If a process allocates `PAGE_EXECUTE_READWRITE` (RWX) memory, and the process is not whitelisted as a known JIT compiler (e.g., `chrome.exe`, `node.exe`).
- **JIT Compiled Code** (Score: **10**): If a known JIT compiler allocates RWX memory (treated as benign but logged).
- **Suspicious WriteCopy** (Score: **80**): If `PAGE_EXECUTE_WRITECOPY` is found in a process not known to be an AV product.

### Network Scanner (`src/network/connection_scanner.py`)
*Line reference: ~Line 245-285*

- **C2 Port Detected** (Score: **75**): Outbound connection on known C2 port (e.g., 4444, 5555, 50050).
- **Suspicious Outbound** (Score: **85**): System process (e.g., `lsass.exe`, `cmd.exe`) making an external connection.
- **Non-Browser HTTPS** (Score: **40**): Process other than a browser using port 443 externally.
- **Data Exfiltration** (Score: **60**): System process connecting to a high port (>10000).
- **Potential DNS Tunnel** (Score: **55**): Non-DNS process connecting externally on port 53.

### Persistence Hunter (`src/persistence/registry_scanner.py`)
*Line reference: ~Line 223-260*

- **Image File Execution Options (IFEO)** (Score: **70**): Hijacking process execution via debugger keys.
- **Shell Open Command** (Score: **65**): Hijacking default file extensions.
- **AppInit_DLLs** (Score: **60**): Global DLL injection via registry.
- **Winlogon Shell/Userinit** (Score: **50**): Logon script hijacking.
- **Scheduled Tasks** (Score: **35**): Common persistence via `schtasks`.
- **Run/RunOnce Keys** (Score: **30**): Standard registry autoruns.
- **LOLBin Usage** (Score: **+25**): If the persistence payload invokes a LOLBin (e.g., `powershell.exe`).
- **Suspicious Path** (Score: **+20**): Payload executes from `\Temp\` or `\Users\Public\`.
- **Active Implant** (Score: **+20**): If the persistence payload executable is *currently running in memory*.

### DLL Inspector (`src/capture/dll_inspector.py`)
*Line reference: ~Line 158-205*

- **DLL Masquerading** (Score: **90**): System DLL (e.g., `kernel32.dll`) loaded from a non-system folder.
- **Hollowed Process** (Score: **80**): Process has abnormally few loaded modules (e.g., `svchost.exe` with < 10 modules).
- **Suspicious Name Pattern** (Score: **75**): DLL name contains "inject", "hook", "payload", etc.
- **Side-Loading (Suspicious Dir)** (Score: **70**): DLL loaded from `\Temp\` or `\Downloads\`.
- **Hijacked DLL Candidate** (Score: **65**): Known vulnerable DLL (e.g., `version.dll`) loaded from a non-system directory.
- **Side-Loading (User Dir)** (Score: **40**): DLL loaded from a standard user directory.

---

## Centralized Correlation Heuristics (`src/correlation/threat_scorer.py`)

The central `ThreatScorer` analyzes the combined timeline.

### Standard Rules (Lines ~108-220)

| Rule # | Detection | Risk Score | MITRE TTP | Code Line |
|--------|-----------|------------|-----------|-----------|
| **1** | **Suspicious Prefetch**: Known malicious executable executed (e.g., mimikatz). | 75 | Varies | Line 108 |
| **2** | **Suspicious Process**: High-risk process actively running in memory. | 60 | Varies | Line 122 |
| **2.1** | **Unusual Directory**: Process running from `temp`, `appdata`, `public`, etc. | +40 | T1036.005 | Line 135 |
| **3** | **Parent Anomaly**: Process running with unexpected parent (e.g. `svchost.exe` not spawned by `services.exe`). | +30 | T1055 | Line 149 |
| **4** | **Timestomping**: File Creation Time is *after* Modification Time. | +50 | T1070.006 | Line 168 |
| **5** | **Lateral Movement Tool**: Execution of `psexec`, `wmic`, `winrs`, etc. | +25 | T1021 | Line 184 |
| **6** | **Registry Persistence**: `run`, `runonce`, `winlogon` keywords in registry artifacts. | +35 | T1547.001 | Line 201 |
| **7** | **Event Log Data**: General marker for log artifacts. | 10 | N/A | Line 215 |

### Novel Cross-Module Rules (Lines ~258-409)

These rules run in `evaluate_cross_module()` and combine data from multiple scanner outputs, representing advanced multi-vector threat detection.

| Rule # | Name | Description | Risk Score | MITRE TTP | Code Line |
|--------|------|-------------|------------|-----------|-----------|
| **8** | **Process-Network Correlation** | A process has BOTH highly suspicious memory regions (e.g., RWX) AND outbound network connections. Flags as likely C2 implant. | 95 | T1071.001, T1055 | Line 292 |
| **9** | **Persistence-Memory Correlation** | A persistent registry entry points to an executable that is currently running and has suspicious memory. Confirms active, persistent implant. | 100 | T1547.001, T1055 | Line 315 |
| **10** | **DLL-Memory Correlation** | A process has BOTH suspiciously injected DLLs AND RWX memory regions. Confirms shellcode/DLL injection. | 95 | T1055.001, T1574.002| Line 333 |
| **11** | **Temporal Correlation** | If 3 or more high-risk events (score >= 50) occur across *different modules* in the same scan window. Indicates coordinated attack. | 90 | T1059, T1055, T1071 | Line 355 |
| **12** | **LOLBin Chain Detection** | If multiple Living-Off-The-Land binaries (e.g., `cmd.exe`, `powershell.exe`, `certutil.exe`) are active in memory simultaneously. | 85 | T1059.001, T1218 | Line 381 |

### Unified Dashboard Score Calculation (`src/main.py`)
*Line reference: ~Line 146*

When using `/dashboard`, a final system-wide Threat Score (0-100) is calculated:
`Unified Score = (Max Risk found * 0.6) + (Average of Top 10 Risks * 0.4)`
This prevents a single isolated medium-risk anomaly from inflating the score, while heavily weighting confirmed critical findings.
*Document version: 2.0 — September 2026*
