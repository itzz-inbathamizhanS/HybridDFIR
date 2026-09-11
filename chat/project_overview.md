# HybridDFIR: A Unified Digital Forensics and Incident Response Framework

## 1. Executive Summary (The "What")
**HybridDFIR** is an advanced, automated Digital Forensics and Incident Response (DFIR) framework. It bridges the gap between traditional dead-disk forensics and volatile memory analysis by combining both into a single, automated, and correlated pipeline. 

Instead of an analyst running dozens of separate tools to piece together what happened during a cyberattack, HybridDFIR automatically ingests evidence (disk images, memory dumps, or live system captures), analyzes artifacts, builds a unified chronological timeline, and scores threats using built-in intelligence heuristics.

### Keywords
`Digital Forensics`, `Incident Response`, `Memory Forensics`, `Disk Forensics`, `Threat Hunting`, `Volatility 3`, `Automated Pipeline`, `Timeline Generation`, `Threat Scoring`, `MITRE ATT&CK`.

---

## 2. The Problem Statement (The "Why")

### Drawbacks in Existing Systems
When a system is compromised (e.g., infected with ransomware or a stealthy rootkit), investigators must answer: *How did they get in? What did they take? Are they still here?*
Traditional DFIR workflows suffer from several major drawbacks:
1. **Siloed Analysis:** Disk analysis (looking at hard drives) and Memory analysis (looking at RAM) are done using entirely separate, disconnected tools. An analyst has to manually cross-reference an IP address found in RAM with a downloaded file found on the disk.
2. **Tool Fatigue:** Investigators must juggle tools like Volatility, Registry Explorer, Event Viewer, and Wireshark. 
3. **Time-Consuming:** Manually parsing Registry hives, prefetch files, and memory dumps takes hours or days. In a live incident, time is the most critical resource.
4. **Steep Learning Curve:** Traditional tools require highly specialized knowledge of operating system internals, making them difficult for junior analysts to use effectively.

### The HybridDFIR Solution
HybridDFIR solves these problems by:
1. **Unifying Data Streams:** It automatically extracts data from both Memory (running processes, network connections, injected DLLs) and Disk (Registry keys, Prefetch files, Event Logs).
2. **Automated Correlation:** It takes all the disparate pieces of evidence, normalizes them, and stitches them into a single, easy-to-read chronological timeline.
3. **Heuristic Threat Scoring:** It automatically scores events based on risk (e.g., scoring a `cmd.exe` process spawned by a Word document as highly suspicious).
4. **Interactive Dashboard:** It provides a live, interactive command-line interface (REPL) and generates beautiful HTML/JSON reports for stakeholders.

---

## 3. Basic Concepts (For Beginners)

If you are new to cybersecurity or forensics, here are the foundational concepts this tool relies on:
- **Disk Forensics:** Examining data saved to a hard drive. This data survives a reboot. Examples include files, Windows Registry (system settings), Prefetch files (records of programs that were run), and Windows Event Logs.
- **Memory (RAM) Forensics:** Examining the volatile memory of a computer. When a computer turns off, this data is lost. Advanced malware often hides *only* in memory to avoid detection. Memory forensics looks for running processes, active network connections, and hidden injected code.
- **Artifact:** A digital footprint left behind by user or system activity (e.g., a log entry showing a successful login).
- **Timeline Analysis:** The process of organizing all digital artifacts chronologically to understand the exact sequence of events during a cyberattack.
- **IOC (Indicator of Compromise):** A specific piece of evidence (like a malicious IP address or a known malware file hash) that strongly suggests a network has been breached.

---

## 4. How It Works (The "How")

HybridDFIR operates in a highly structured pipeline, managed by the `src/main.py` orchestrator.

### Phase 1: Evidence Intake (`src/intake/`)
- Takes an evidence file (e.g., `memory.raw` or `disk.E01`).
- Validates the file format and securely calculates cryptographic hashes (SHA-256, MD5) to ensure the evidence has not been tampered with.
- Catalogs the evidence into a central `CaseManager`.

### Phase 2: Artifact Extraction (`src/memory/` and `src/disk/`)
- **Memory Extraction:** Uses a wrapper around the powerful `Volatility 3` engine to extract running processes, parent/child process relationships, and hidden injected code.
- **Disk Extraction:** Parses Windows Prefetch files (to see what executed), Registry hives (to find persistence mechanisms like run keys), and Event Logs.

### Phase 3: Correlation & Threat Scoring (`src/correlation/`)
- **Timeline Builder:** Takes all the extracted data (disk + memory) and standardizes them into `TimelineEvent` objects. It sorts everything chronologically so the analyst can see exactly what happened second-by-second.
- **Threat Scorer:** Evaluates the timeline against security heuristics. For example, if a process name is highly random (`h8f92j.exe`) or if a system process is running from the wrong folder, it assigns a high "Risk Score" and maps it to a MITRE ATT&CK tactic.

### Phase 4: Reporting (`src/response/`)
- Compiles all metadata, the timeline, and the detected threats into a standardized JSON format.
- Generates a polished, interactive HTML dashboard for easy viewing and sharing with non-technical stakeholders.

---

## 5. Architecture & Component Explanation (The "Where" & "What")

Here is a breakdown of the codebase and why each component exists:

| Module | Purpose | Why it's used |
|--------|---------|---------------|
| `src/main.py` | The orchestrator and REPL interface. | Provides the interactive `/dashboard` shell for the user and wires all other modules together. |
| `src/core/case_manager.py` | Manages state. | Keeps track of the current investigation, assigning unique IDs and storing findings securely. |
| `src/intake/ingest_image.py` | Secure file ingestion. | Ensures evidence integrity by hashing files before they are processed. |
| `src/capture/live_ram.py` | Live system capture. | Allows the tool to run directly on an infected machine to dump its RAM safely. |
| `src/memory/volatility_wrapper.py` | Interfaces with Volatility 3. | Volatility is the industry standard for memory analysis; this wrapper automates it so the user doesn't have to run manual commands. |
| `src/disk/artifact_analyzer.py` | Parses disk artifacts. | Extracts critical forensic data from the file system. |
| `src/correlation/timeline_builder.py`| Merges evidence. | Solves the core problem of siloed data by merging memory and disk artifacts into one timeline. |
| `src/correlation/threat_scorer.py` | Automated intelligence. | Applies rules to highlight dangerous activity so the analyst doesn't have to read thousands of benign logs. |
| `src/response/report_generator.py` | HTML/JSON Export. | Allows analysts to share findings with management or other security tools. |

---

## 6. Technology Stack

- **Language:** Python 3.10+ (Chosen for its robust ecosystem in data processing and cybersecurity).
- **CLI Framework:** `rich` (Used for creating the beautiful, colorful, and interactive terminal dashboard, tables, and progress bars).
- **Core Dependencies:** 
  - `pytest` (For robust unit and integration testing).
  - `pyflakes` (For static code analysis and maintaining code hygiene).
- **External Integration:** Interacts with local operating system APIs (via `ctypes` on Windows) for live RAM capture and system enumeration, and interfaces with the `Volatility 3` binary.
- **Data Formats:** Heavy use of `JSON` for internal state transfer and external reporting; HTML generation for user-facing reports.

---

## 7. Use Cases (When & Where to use it)

1. **Incident Response (Live Triage):**
   A security operations center (SOC) gets an alert about a suspicious server. An analyst deploys HybridDFIR directly to the server, runs `/capture` to grab memory and artifacts, and instantly gets a threat report highlighting a malicious injected DLL.
2. **Post-Mortem Forensics (Dead-Disk Analysis):**
   A laptop is seized during an investigation. The disk is imaged and passed to HybridDFIR. The tool processes the image overnight and presents a timeline showing exactly when the user downloaded a file, executed it, and when the malware added a registry persistence key.
3. **Threat Hunting:**
   A security team proactively scans their endpoints. They use the `/persistence` and `/network` commands within the interactive dashboard to hunt for hidden connections and auto-start registry keys across their environment.

---

## 8. Conclusion
HybridDFIR transforms a highly manual, segmented, and tedious process into a unified, automated pipeline. By automatically correlating what is happening in live memory with what is permanently stored on disk, it drastically reduces the time it takes to understand a cyberattack and empowers analysts of all skill levels to perform advanced forensic investigations.
