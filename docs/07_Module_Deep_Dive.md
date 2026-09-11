# Module Deep Dive Reference

This document exhaustively details every module in the framework.

## 1. `src/capture/` (Memory Acquisition & Inspection)
**Purpose:** Interfaces with system memory, either via native APIs or external drivers.

- **`live_ram.py`**: Controls the `winpmem` driver. It attempts to load the kernel driver, dump physical RAM to a `.raw` file, and handles unloading. Includes fallback logic.
- **`native_ram.py`**: The core Win32 memory scanner. Uses `VirtualQueryEx` to iterate through all memory pages of every active process, inspecting memory protections (`PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_WRITECOPY`). Features a prefix-based OEM whitelist to filter out benign drivers from Dell, Intel, HP, etc.
- **`dll_inspector.py`**: Uses `CreateToolhelp32Snapshot` to map DLLs loaded into each process. Detects hollowing, masquerading, and side-loading.

## 2. `src/network/` (Network Intelligence)
**Purpose:** Maps live networking to processes without `netstat` binaries.

- **`connection_scanner.py`**: Calls `iphlpapi.dll` via `ctypes`. It specifically invokes `GetExtendedTcpTable` and `GetExtendedUdpTable`, mapping every local/remote IP and port back to a Process ID (PID). It contains threat intelligence heuristics for common C2 ports and unexpected system process outbound behavior.

## 3. `src/persistence/` (Persistence Hunting)
**Purpose:** Finds registry keys and tasks designed to survive reboots.

- **`registry_scanner.py`**: Uses Python's built-in `winreg` library to scan `HKLM` and `HKCU` Run keys, Winlogon keys, AppInit_DLLs, and Image File Execution Options. It also wraps `schtasks /query` to find hidden scheduled tasks, mapping them against LOLBin usage.

## 4. `src/disk/` (Disk Artifact Extraction)
**Purpose:** Extracts offline forensic artifacts from mounted disk images.

- **`artifact_extractor.py`**: The orchestrator for disk extraction. It knows the exact paths to `SYSTEM`, `SOFTWARE`, `SAM` hives, and the `C:\Windows\Prefetch` directory.
- **`fs_parser.py`**: A raw filesystem parser used when analyzing raw `.dd` or `.e01` images (vs live analysis).

## 5. `src/correlation/` (Threat Intelligence Engine)
**Purpose:** Centralizes and analyzes the output of all scanners.

- **`timeline_builder.py`**: Consumes findings from memory, disk, network, and persistence. Converts them into a unified chronological timeline list. Features `add_events` and `save_timeline` to persist the intermediate JSON.
- **`threat_scorer.py`**: The brain of the operation. Contains 12 heuristic rules (7 standard, 5 cross-module) mapped to MITRE ATT&CK TTPs. Outputs standard `CorrelatedEvent` dictionaries.

## 6. `src/response/` (Reporting)
**Purpose:** Formats the results for human analysts.

- **`report_generator.py`**: Takes the unified findings and generates two outputs:
  1. A machine-readable `JSON` file for integration with external SIEMs.
  2. A standalone `HTML` dashboard with embedded CSS/JS, featuring charts, timelines, and threat breakdowns, designed to be opened in isolated environments.

## 7. `src/intake/` (Evidence Handling)
**Purpose:** Chain of custody and validation.

- **`ingest_image.py` & `validator.py`**: Computes SHA-256 hashes of disk/memory dump files before processing, ensuring forensic integrity.

## 8. `src/config/` (Schemas & Settings)
**Purpose:** Defines the data contracts.

- **`data_models.json`**: Strict JSON schema defining `CorrelatedEvent`, `RiskScore`, and `ThreatIndicator`. Ensures all modules output compatible data.
- **`settings.py`**: Global framework configurations, directory paths (like `OUTPUT_DIR`), and log levels.
