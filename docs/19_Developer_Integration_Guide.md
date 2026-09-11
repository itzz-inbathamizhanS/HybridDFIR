# 19. Developer Integration Guide

The Hybrid Forensics Framework is designed as a modular, top-level integration tool. This guide explains how to write new scanner modules and connect them into the Correlation Engine.

---

## 1. The Zero-Dependency Paradigm

This framework enforces a strict zero-dependency rule to ensure portability across air-gapped forensic environments.
**Rule:** You may only use the Python Standard Library and `ctypes`.

### Using `ctypes` for Win32 API Calls

When integrating a new forensic collection method (e.g., querying the NTFS Master File Table or inspecting ETW traces), you must interact directly with the Windows API.

**Example: Mapping a DLL function**
```python
import ctypes
import ctypes.wintypes as wintypes

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Define argument types and return types strictly
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
```

---

## 2. Standardizing Output for the Correlation Engine

To integrate your new module into the unified dashboard, your scanner must return a list of dictionaries matching the `CorrelatedEvent` standard.

### Required Fields for Every Finding
When your scanner detects an anomaly, yield a dictionary with the following structure:
```python
finding = {
    "module": "YourModuleName",      # The name of your scanner
    "type": "SUSPICIOUS_BEHAVIOR",   # The category of the threat
    "timestamp": "2026-09-10T12:00:00", # ISO-8601 timestamp (or "UNKNOWN")
    "process_name": "malware.exe",   # Process associated with the event
    "pid": 1337,                     # Process ID (int)
    "risk_score": 85,                # Integer between 0 and 100
    "description": "Detected anomalous behavior in thread injection.",
    "threat_labels": ["Injected Thread", "Evasion"] # High-level tags
}
```

---

## 3. Registering Your Module in `main.py`

Once your scanner is written, you must hook it into the main dashboard execution loop in `src/main.py`.

1. **Import your class:**
   ```python
   from src.your_folder.your_scanner import YourScannerClass
   ```
2. **Instantiate and run inside the dashboard block:**
   ```python
   scanner = YourScannerClass(console)
   your_findings = scanner.scan()
   ```
3. **Pass findings to the Correlation Engine:**
   ```python
   all_events.extend(your_findings)
   ```

---

## 4. Expanding the Correlation Engine (`src/correlation/threat_scorer.py`)

If your new module provides context that could correlate with existing modules (e.g., you wrote an ETW scanner and want to correlate it with the Registry Persistence Scanner), you must add a new rule to the `ThreatScorer` class.

**Adding a Correlation Rule:**
Navigate to `src/correlation/threat_scorer.py` and modify `analyze_cross_correlations()`. You can cross-reference your new data by extracting process names or PIDs and comparing them against the `memory_findings` or `network_findings` lists.
