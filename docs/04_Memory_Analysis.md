# Memory Analysis Module

> Modules: `src/capture/` & `src/memory/` — Live RAM Inspection, Process Lineage, and DLL Analysis

---

## 1. Overview

Memory analysis in this framework operates entirely offline, using native Win32 APIs via Python's `ctypes` module. The framework avoids deploying kernel drivers or third-party binaries, making it ideal for hardened, air-gapped endpoints.

The module provides three distinct capabilities:
1. **Live RAM Inspection:** Scans raw memory regions for RWX shellcode.
2. **Process Lineage Analysis:** Builds parent-child process trees to detect masquerading.
3. **DLL Inspection:** Parses PE structures to detect module hollowing and unbacked executables.

*(Note: Legacy Volatility 3 integration for offline `.raw` image analysis is still supported via `src/memory/volatility_wrapper.py` but is no longer the primary engine).*

---

## 2. Module Structure

```
src/capture/                         # Native Live Inspection
├── native_ram.py                    # Zero-binary memory scanner (RWX hunting)
├── dll_inspector.py                 # PE parsing & entropy (Module hollowing)
└── live_ram.py                      # Forensic capture engine (scan + MiniDumps)

src/memory/                          # Process Lineage & Legacy
├── process_tree.py                  # Process lineage mapping (Parent/Child)
├── process_scanner.py               # Vol3 legacy interface
└── volatility_wrapper.py            # Vol3 CLI subprocess wrapper
```

---

## 3. Core Native Components

### 3.1 `NativeLiveRAMAnalyzer` (Memory Scanner)

**File:** `src/capture/native_ram.py`

A zero-binary, driverless live Windows process memory scanner. It walks process address spaces using `VirtualQueryEx`.

**Heuristic Rules:**
- `RWX_SHELLCODE_INJECTION` (Score: 90): Detects `MEM_COMMIT` + `PAGE_EXECUTE_READWRITE` (classic shellcode).
- `LARGE_PRIVATE_EXECUTABLE` (Score: 60): Detects `PAGE_EXECUTE_READ` on `MEM_PRIVATE` regions > 1 MiB.

### 3.2 `ProcessTreeBuilder` (Lineage Mapping)

**File:** `src/memory/process_tree.py`

Uses `kernel32.CreateToolhelp32Snapshot` to map process lineages and build a unified Process Tree.

**Heuristics:**
- `SUSPICIOUS_SYSTEM_PARENT`: Detects when critical OS processes (e.g., `lsass.exe`, `winlogon.exe`) spawn suspicious child binaries (`cmd.exe`, `powershell.exe`).
- `ORPHANED_PROCESS`: Flags processes lacking a valid active parent, indicative of recycled PIDs or hollowed injections.

### 3.3 `DLLInspector` (Module Hollowing)

**File:** `src/capture/dll_inspector.py`

Uses `psapi.EnumProcessModules` and raw PE structure parsing to analyze loaded DLLs.

**Heuristics:**
- `HIGH_ENTROPY_PE`: Calculates Shannon Entropy of DLL text sections. High entropy (>7.2) flags packed or encrypted implants.
- `UNBACKED_EXECUTABLE`: Identifies DLLs loaded into memory that lack corresponding valid disk files, a strong indicator of Reflective DLL Injection.

---

## 4. Pipeline Integration

Findings from the Native RAM Scanner, Process Tree Builder, and DLL Inspector are emitted as structured dictionaries. 

The `ThreatScorer` in the Correlation Engine receives these findings and triggers **Cross-Module Correlation** (e.g., matching a process with an injected DLL to an active outbound network connection).

**Example Output Payload:**

```json
{
  "pid": 1337,
  "process_name": "svchost.exe",
  "threat_label": "UNBACKED_EXECUTABLE",
  "risk_score": 85,
  "description": "DLL loaded at 0x7FF6A4B20000 has no valid backing file on disk.",
  "mitre_attack_ttps": ["T1055.001"]
}
```

---

*Document version: 2.0 — September 2026*
