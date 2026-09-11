# Command Line & REPL Interface

The Hybrid Forensics Framework can be driven entirely via command-line arguments (for automated scripting) or via the Interactive REPL (for manual incident response).

## Starting the Framework

**Enter Interactive REPL:**
```powershell
python src/main.py
```

## Help Output

You can always view the full CLI syntax by running:
```powershell
python src/main.py --help
```

**Full Help Syntax:**
```text
usage: main.py [-h] [--dashboard] [--process-tree] [--scan-ioc FILE]
               [--scan-artifacts DIR] [--scan] [--network] [--persistence]
               [--dllinspect] [--case-id ID] [--create-case NAME]
               [--analyst ANALYST] [--desc DESC] [--case-info ID]
               [--verify-case ID] [--critical] [--image FILE]
               [--type {memory,disk,hybrid}] [--mount DIR] [--doctor]
               [--self-test] [--license-check]

Hybrid Forensics Framework - High-Assurance CLI
================================================
A unified command-line interface for multi-module forensic analysis in air-gapped environments.
It natively queries Win32 APIs for memory, network, DLLs, and persistence mechanisms,
cross-correlates the findings, and generates a unified offline HTML report & JSON case export.

options:
  -h, --help            show this help message and exit

Operational Modes:
  --dashboard           Execute the Unified Threat Dashboard. Runs ALL live native modules
                        (Memory, Network, Persistence, DLLs), correlates findings using Rules 8-12,
                        and generates an offline HTML report & CASE_EXPORT JSON.
  --process-tree        Analyze live process lineage. Builds a visual parent-child process tree
                        and flags masquerading processes (e.g. svchost.exe without services.exe parent).
  --scan-ioc FILE       Ingest a local JSON file (STIX-like) containing Indicators of Compromise
                        (IPs, Domains, Hashes) and cross-reference them against active memory and networks.
  --scan-artifacts DIR  Perform deep analysis of disk artifacts (Registry, Prefetch) at the given mount point.

Individual Live Scanners:
  --scan                [Module 1] Run native live RAM inspection. Detects RWX memory regions and shellcode.
  --network             [Module 2] Run network connection scanner. Uses iphlpapi to map PIDs to outbound connections.
  --persistence         [Module 3] Run registry persistence hunter. Scans Run, RunOnce, and Services keys.
  --dllinspect          [Module 4] Run DLL injection detector. Parses PE structures to detect module hollowing.

Case Management (Required for --dashboard):
  --case-id ID          The target Case ID to use for storing findings and correlating data.
  --create-case NAME    Create a new secure case directory with the specified name.
  --analyst ANALYST     Specify analyst name when creating a new case (Default: SYSTEM).
  --desc DESC           Optional description when creating a case.
  --case-info ID        Display metadata and summary for the specified Case ID.
  --verify-case ID      Cryptographically verify the integrity of the specified Case ID (Hash chaining).

Analysis Options:
  --critical            Filter dashboard/scanner output to display only CRITICAL severity threats.

Legacy Offline Image Analysis:
  --image FILE          Path to offline evidence image (RAW/E01).
  --type {memory,disk,hybrid}
                        Type of offline analysis to perform.
  --mount DIR           Mount point directory for disk analysis.

Diagnostics & Compliance:
  --doctor              Verify environment compatibility, admin privileges, and native module access.
  --self-test           Run the automated end-to-end framework test (CI/CD pipeline simulation).
  --license-check       Audit and display the open-source license compliance report.

Examples:
  1. Start interactive shell:
     python src/main.py

  2. Create a new forensic case:
     python src/main.py --create-case "Ransomware Incident" --analyst "John Doe" --desc "Server01"

  3. Run the Unified Cross-Correlation Dashboard on the live system:
     python src/main.py --dashboard --case-id CASE-XXXXXXXX-XXXXXX

  4. Scan Process Lineage (Parent/Child relationships):
     python src/main.py --process-tree

  5. Scan System with Offline Indicators of Compromise:
     python src/main.py --scan-ioc indicators.json

  6. Verify environment health & run self-tests:
     python src/main.py --doctor
     python src/main.py --self-test
```

---

## Case Management

All modern forensic investigations should be bound to a Case ID. Creating a case establishes an Evidence Graph and an immutable Audit Log.

**Create a New Case:**
```powershell
python src/main.py --create-case "Operation Shadow" --analyst "Admin" --desc "Investigation of initial access"
```

**View Case Information:**
```powershell
python src/main.py --case-info "CASE-XXXXXXXX-XXXXXX"
```

**Verify Case Integrity:**
```powershell
python src/main.py --verify-case "CASE-XXXXXXXX-XXXXXX"
```

---

## The Unified Dashboard

The "Dashboard" command runs all active scanning engines simultaneously, performs cross-module correlation, aggregates findings, and saves the assessment to your Case ID.

**REPL:** `❯ /dashboard`
**REPL (Critical Only):** `❯ /dashboard --critical`
**CLI:** `python src/main.py --dashboard --case-id "CASE-XXXXXXXX-XXXXXX"`

---

## Individual Scanners

You can run individual modules if you only need specific forensic data. All commands save their detailed output as JSON files in the `output/` directory.

### Process Lineage & Anomalies
Maps process trees and flags suspicious parent-child relationships (e.g., `cmd.exe` spawned by `lsass.exe`).
**CLI:** `python src/main.py --process-tree`

### Deep Artifact Scanner
Extracts and analyzes metadata from Windows Registry Hives, Event Logs, and Prefetch files for known threats.
**CLI:** `python src/main.py --scan-artifacts "C:\"`

### Offline IOC Engine
Cross-references live memory, processes, and network connections against an offline JSON indicator file (STIX-like format).
**CLI:** `python src/main.py --scan-ioc indicators.json`

### Memory Inspection
Scans live RAM for injected shellcode and anomalous protections using Win32 APIs.
**REPL:** `❯ /scan` or `/scan --critical`
**CLI:** `python src/main.py --scan`

### Network Intelligence
Enumerates active TCP/UDP connections and flags C2 traffic using `iphlpapi.dll`.
**REPL:** `❯ /network` or `/network --threats`
**CLI:** `python src/main.py --network`

### Persistence Hunter
Scans the registry for autorun mechanisms and active implants.
**REPL:** `❯ /persistence` or `/persistence --threats`
**CLI:** `python src/main.py --persistence`

### DLL Inspector
Detects DLL side-loading, masquerading, and hollowed processes.
**REPL:** `❯ /dllinspect`
**CLI:** `python src/main.py --dllinspect`

---

## Image Analysis (Offline/Post-Mortem)

If analyzing memory dumps or disk images instead of the live system, use the `/analyze` or `/capture` commands.

### Capture Memory to Disk
Uses `winpmem` to create a `.raw` memory dump and run analysis on it.
**REPL:** `❯ /capture` or `/capture --driver`

### Analyze Existing Dump
Runs the Volatility 3 wrapper or disk artifact extraction on a file.
**REPL:** `❯ /analyze memory path\to\dump.raw`
**REPL:** `❯ /analyze disk path\to\image.dd C:\mount_point`
**CLI:** `python src/main.py --image path\to\dump.raw --type memory`
