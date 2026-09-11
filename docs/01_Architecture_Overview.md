# Hybrid Forensics Framework - Architecture Overview

## Introduction

The Hybrid Forensics Framework is an advanced, multi-module cybersecurity analysis tool designed for air-gapped incident response. Unlike traditional forensics tools that operate in silos, this framework correlates artifacts from live memory, disk (registry/event logs), live network connections, persistence mechanisms, and DLL structures.

By unifying these separate forensic disciplines under one single interface, the framework produces an aggregate "System Threat Score" that gives Incident Responders a high-level summary of the system's compromise status.

## Core Architecture

The architecture is built as a pipeline, where discrete scanning engines pass structured JSON data to a central correlation engine, which then generates unified HTML and JSON reports.

### The 5 Scanning Engines

1. **Native Memory Scanner (`src/capture/native_ram.py`)**
   - **Method:** Zero-binary, driverless live RAM inspection using Win32 API (`VirtualQueryEx`, `ReadProcessMemory`).
   - **Purpose:** Identifies malicious memory allocations (e.g., RWX memory) indicating injected shellcode.

2. **Network Intelligence Scanner (`src/network/connection_scanner.py`)**
   - **Method:** TCP/UDP enumeration via Win32 `iphlpapi.dll` (`GetExtendedTcpTable`, `GetExtendedUdpTable`).
   - **Purpose:** Maps live connections to processes, detecting C2 beacons, data exfiltration patterns, and suspicious outbound traffic.

3. **Persistence Hunter (`src/persistence/registry_scanner.py`)**
   - **Method:** Scans live registry (`winreg`), WMI subscriptions, and Scheduled Tasks.
   - **Purpose:** Identifies malware persistence mechanisms (autorun keys, hijacked services) and flags active vs. dormant implants.

4. **DLL Injection Detector (`src/capture/dll_inspector.py`)**
   - **Method:** Enumerates loaded modules per process via `CreateToolhelp32Snapshot`.
   - **Purpose:** Detects DLL side-loading, DLL masquerading, hijacked modules, and hollowed processes.

5. **Disk Artifact Extractor (`src/disk/artifact_extractor.py`)**
   - **Method:** Parses raw registry hives, prefetch files, and Windows Event Logs.
   - **Purpose:** Reconstructs historical execution timelines.

### Data Flow

1. **Intake (`src/intake/`)**: Hashes and validates evidence files (if running against static dumps instead of live system).
2. **Scan (`src/capture/`, `src/network/`, `src/persistence/`)**: Scanning engines run concurrently or sequentially to generate raw findings.
3. **Normalize (`src/correlation/timeline_builder.py`)**: Raw findings from all modules are converted into standard `CorrelatedEvent` JSON objects (defined in `src/config/data_models.json`).
4. **Correlate (`src/correlation/threat_scorer.py`)**: The `ThreatScorer` evaluates the timeline and cross-references data between modules (e.g., checking if a process with a persistence key also has an active network connection).
5. **Respond (`src/response/report_generator.py`)**: Findings are rendered into a standalone HTML dashboard and a machine-readable JSON report.

## Design Philosophy

- **Zero-Dependency Core**: Key modules use Python's `ctypes` to interface directly with the Windows API, removing the need for external C binaries or kernel drivers that could trigger Anti-Virus (AV).
- **Extensible Schema**: All data passed between modules adheres to strict JSON schemas, ensuring that future integrations (like YARA scanning) can plug into the `ThreatScorer` effortlessly.
- **Air-Gapped Operation**: Generates fully self-contained HTML reports with inline CSS/JS, ensuring it works on isolated incident response laptops.
