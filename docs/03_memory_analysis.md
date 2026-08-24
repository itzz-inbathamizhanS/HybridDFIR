# Memory Analysis Module

> Modules: `src/memory/` & `src/capture/` — Offline Memory Analysis & Live RAM Inspection

---

## 1. Overview

Memory analysis in this framework is split across two subsystems that serve different forensic objectives:

| Subsystem | Location | Purpose | Requires Admin |
|---|---|---|---|
| **Offline Memory Analysis** | `src/memory/` | Analyzes pre-captured memory images using Volatility 3 | No |
| **Live RAM Inspection** | `src/capture/` | Scans the current system's live process memory using native Win32 APIs | Yes |

Both subsystems produce structured output conforming to the framework's JSON schemas, and both feed into the correlation engine.

---

## 2. Module Structure

```
src/memory/                          # Offline analysis
├── __init__.py                      # Exports: ProcessScanner, VolatilityWrapper
├── process_scanner.py               # High-level process extraction
└── volatility_wrapper.py            # Volatility 3 CLI subprocess wrapper

src/capture/                         # Live inspection (Phase 1)
├── native_ram.py                    # Zero-binary driverless memory scanner
└── live_ram.py                      # Forensic capture engine (scan + MiniDumps)
```

---

## Part A: Offline Memory Analysis (`src/memory/`)

### 3. `VolatilityWrapper` Class

**File:** `src/memory/volatility_wrapper.py`

Thin wrapper around the local Volatility 3 binary. Executes plugins as subprocesses and parses their JSON output.

#### Constructor

```python
VolatilityWrapper(memory_image_path: str, vol_bin: str = "vol")
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `memory_image_path` | `str` | — | Path to the memory image file |
| `vol_bin` | `str` | `"vol"` | Name or path of the Volatility 3 executable |

Raises `FileNotFoundError` if the memory image does not exist.

#### `run_plugin(plugin_name: str) → list`

Executes a Volatility 3 plugin and returns the parsed JSON output.

**Command constructed:**
```
vol -f <memory_image> -r json <plugin_name>
```

**Graceful Degradation:**

| Condition | Behavior |
|---|---|
| Volatility not installed | Prints warning, returns `[]` |
| Plugin execution fails | Prints warning, returns `[]` |
| Non-JSON output | Catches `JSONDecodeError`, returns `[]` |

This ensures the pipeline continues even when Volatility is unavailable — the framework was designed to work with or without it.

---

### 4. `ProcessScanner` Class

**File:** `src/memory/process_scanner.py`

High-level scanner that extracts process lists from memory images and formats them to match the `MemoryProcess` schema.

#### `extract_running_processes() → list`

Runs the `windows.pslist.PsList` plugin and maps Volatility's output columns to the framework's standardized format.

**Column Mapping:**

| Volatility Column | Framework Field |
|---|---|
| `PID` | `pid` |
| `PPID` | `ppid` |
| `ImageFileName` | `process_name` |
| `ImageFileName` | `path` (deeper plugins needed for full paths) |
| `Handles` | `handles_count` |

**Output — `MemoryProcess` schema:**

```json
{
  "pid": 1234,
  "ppid": 456,
  "process_name": "cmd.exe",
  "path": "cmd.exe",
  "handles_count": 150
}
```

#### `check_for_injected_code() → list`

Runs the `windows.malfind.Malfind` plugin to detect injected or hidden code within process memory regions. Returns raw Volatility output for correlation.

---

### 5. `MemoryProcess` Data Schema

```json
{
  "type": "object",
  "required": ["pid", "ppid", "process_name", "path"],
  "properties": {
    "pid": { "type": "integer" },
    "ppid": { "type": "integer" },
    "process_name": { "type": "string" },
    "path": { "type": "string" },
    "handles_count": { "type": "integer" }
  }
}
```

---

## Part B: Live RAM Inspection (`src/capture/`)

### 6. `NativeLiveRAMAnalyzer` Class

**File:** `src/capture/native_ram.py`

The Phase 1 core component — a zero-binary, driverless live Windows process memory scanner. Uses **only** native Win32 APIs via Python's `ctypes` module. No third-party kernel drivers, no `psutil`.

#### 6.1 Win32 APIs Used

| API Function | Source DLL | Purpose |
|---|---|---|
| `IsUserAnAdmin` | `shell32.dll` | Validates administrator privileges |
| `CreateToolhelp32Snapshot` | `kernel32.dll` | Creates a snapshot of all running processes |
| `Process32First` / `Process32Next` | `kernel32.dll` | Iterates through the process snapshot |
| `OpenProcess` | `kernel32.dll` | Opens a handle to a target process |
| `VirtualQueryEx` | `kernel32.dll` | Queries memory region attributes for a process |
| `CloseHandle` | `kernel32.dll` | Releases process and snapshot handles |

#### 6.2 Win32 Structures

Two `ctypes.Structure` subclasses map native Windows data structures:

- **`MEMORY_BASIC_INFORMATION`** — Describes a memory region's base address, size, state, protection, and type
- **`PROCESSENTRY32`** — Describes a process entry from the Toolhelp32 snapshot (PID, parent PID, executable name)

#### 6.3 Scan Workflow

```
1. Validate Administrator Privileges
   └─ shell32.IsUserAnAdmin()
   └─ If not admin → display rich error panel → return []

2. Enumerate All Processes
   └─ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)
   └─ Process32First → Process32Next loop
   └─ Result: List[(pid, exe_name)]

3. Walk Each Process Address Space
   └─ OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
   └─ VirtualQueryEx loop (address 0 → end of address space)
   └─ For each committed region → apply heuristic rules
   └─ CloseHandle(process)

4. Return All Findings
   └─ List[dict] with threat labels and risk scores
```

#### 6.4 Threat Heuristics

The scanner applies four heuristic rules to every committed memory region:

| Heuristic | Threat Label | Risk Score | Trigger Condition |
|---|---|---|---|
| **A1** | `RWX_SHELLCODE_INJECTION` | 90 | `MEM_COMMIT` + `PAGE_EXECUTE_READWRITE` (classic shellcode) |
| **A2** | `RWX_WRITECOPY_SUSPICIOUS` | 80 | `MEM_COMMIT` + `PAGE_EXECUTE_WRITECOPY` (rare, often malicious) |
| **B** | `LARGE_PRIVATE_EXECUTABLE` | 60 | `PAGE_EXECUTE_READ` on `MEM_PRIVATE` region > 1 MiB (hollowed section) |
| **C** | `RWX_GUARD_STAGED_PAYLOAD` | 75 | Executable page with `PAGE_GUARD` modifier (staged payload) |

#### 6.5 JIT & AV Whitelisting

To suppress false positives, known legitimate processes are whitelisted to a risk score of 10:

**JIT Processes** (V8 / .NET JIT compilers):
```
chrome.exe, brave.exe, msedge.exe, msedgewebview2.exe,
node.exe, Code.exe, Antigravity IDE.exe, powershell.exe,
pwsh.exe, Creative Cloud UI Helper.exe,
HPCommRecovery.exe, HPSystemEventUtilityHost.exe
```

**AV Processes** (security products using copy-on-write):
```
QHActiveDefense.exe, QHSafeTray.exe, MsMpEng.exe
```

Whitelisted findings are **not suppressed from JSON output** — they are only filtered from the CLI display (risk < 50 hidden from table). This preserves full forensic visibility in reports.

#### 6.6 Output Format

Each finding is a dictionary:

```json
{
  "pid": 12456,
  "process_name": "suspicious.exe",
  "base_address": "0x00007FF6A4B20000",
  "region_size": 2097152,
  "region_size_human": "2.0 MiB",
  "protection": 64,
  "protection_name": "PAGE_EXECUTE_READWRITE",
  "mem_type": 131072,
  "mem_type_name": "MEM_PRIVATE",
  "threat_label": "RWX_SHELLCODE_INJECTION",
  "risk_score": 90,
  "scan_timestamp_utc": "2026-08-23T15:53:42Z"
}
```

#### 6.7 Pipeline Integration

The `findings_to_correlated_events()` method converts raw findings into `CorrelatedEvent` schema objects:

```python
events = analyzer.findings_to_correlated_events(findings)
# Each event has: timestamp, source_module, event_type, description, risk_score
```

Events with risk ≥ 50 are typed as `THREAT_DETECTED`; lower scores are typed as `INFO_BENIGN_ALLOCATION`.

---

### 7. `LiveRAMCapturer` Class

**File:** `src/capture/live_ram.py`

The deep forensic capture engine. While `/scan` is a lightweight read-only inspection, `/capture` performs a full forensic acquisition:

#### 7.1 Three-Phase Capture Process

```
Phase 1: Memory Scan
├── Run NativeLiveRAMAnalyzer.scan_live_ram()
├── Collect all suspicious memory regions
└── Save structured findings as scan_results.json

Phase 2: Process Memory Dumps
├── Identify all PIDs with risk_score >= 50
├── MiniDumpWriteDump() via dbghelp.dll for each suspicious PID
├── Save .dmp files to process_dumps/ directory
└── Generate dump_manifest.json

Phase 3: Evidence Package
├── Calculate total capture size
└── Display summary panel with output paths
```

#### 7.2 MiniDump Creation

Process dumps are created using `dbghelp.dll!MiniDumpWriteDump` via `ctypes`:

```python
dbghelp.MiniDumpWriteDump(
    h_process,          # Handle to target process
    pid,                # Process ID
    h_file,             # Handle to output .dmp file
    MiniDumpWithFullMemory,  # Full memory dump flag (0x00000002)
    None, None, None    # No exception/user info/callback
)
```

#### 7.3 Optional Driver Mode

When invoked with `--driver`, the capturer first attempts a full physical RAM dump using `winpmem.exe`. If the driver is blocked (common on hardened endpoints), it automatically falls back to native capture mode.

#### 7.4 Output Directory Structure

```
output/native_capture_<timestamp>/
├── scan_results.json       # Full scan findings + correlated events
├── dump_manifest.json      # Status of each process dump attempt
└── process_dumps/
    ├── chrome.exe_pid1234.dmp
    ├── suspicious.exe_pid5678.dmp
    └── ...
```

---

## 8. CLI Commands

| Command | Module Used | Description |
|---|---|---|
| `/scan` | `NativeLiveRAMAnalyzer` | Quick read-only memory inspection — displays table + saves JSON |
| `/capture` | `LiveRAMCapturer` | Deep forensic capture: scan + process MiniDumps |
| `/capture --driver` | `LiveRAMCapturer` | Try winpmem driver first, then native fallback |
| `/analyze <type> <path>` | `ProcessScanner` | Analyze an existing offline memory image via Volatility |

---

## 9. Test Coverage

The memory module is covered by `tests/test_memory.py`:

| Test Case | Description |
|---|---|
| `test_extract_running_processes` | Mocks Volatility 3 subprocess output, verifies process extraction and schema mapping |

Run tests:
```bash
pytest tests/test_memory.py -v
```

---

*Document version: 1.0 — August 2026*
