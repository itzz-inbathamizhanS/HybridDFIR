# Understanding the Hybrid Forensics Framework

Welcome to the definitive guide to the **Hybrid Forensics Framework**. Whether you are a security analyst, a software engineer, or a contributor, this document will explain everything you need to know about the project—from its core philosophy down to its low-level implementation.

---

## 1. What is this project?

The Hybrid Forensics Framework is a modular, air-gapped incident response and digital forensics tool. It is designed to extract, analyze, and correlate digital evidence from both **live system memory (RAM)** and **dead disk images**. 

It acts as an automated forensic pipeline that takes raw artifacts, processes them, correlates events across memory and disk into a unified timeline, and scores them for malicious activity—all while generating readable, offline reports.

---

## 2. Why was this project built? (The Problem)

Modern digital forensics faces three major challenges during incident response:

1. **The Endpoint Detection & Response (EDR) Barrier:** 
   Traditional memory capture tools (like `winpmem`) rely on third-party kernel drivers to read physical RAM. Modern Windows security features (like VBS, HVCI) and aggressive EDR solutions often block these unknown drivers, preventing incident responders from acquiring memory when they need it most.
2. **The Air-Gap Requirement:**
   During a severe breach, infected machines are often physically disconnected from the network (air-gapped) to stop lateral movement. Tools that rely on cloud intelligence, external APIs, or CDNs fail entirely in these environments.
3. **The Silo Problem:**
   Forensic analysts usually have to use one set of tools for disk analysis (e.g., parsing Registry/Prefetch) and another entirely different set for memory analysis (e.g., Volatility). Correlating a process running in memory with an artifact on disk is a slow, manual, and error-prone process.

### The Solution
This framework solves these problems by:
1. Implementing a **zero-binary, driverless live memory scanner** that uses native Windows APIs to inspect memory without triggering EDR driver blocks.
2. Operating **100% offline**, requiring zero network connectivity to function or render reports.
3. Automatically **correlating disk and memory events** into a single chronological timeline and scoring them for threats.

---

## 3. Core Working of the Project (High Level)

The framework operates in a linear pipeline divided into distinct phases:

1. **Intake (`src/intake/`)**: 
   The pipeline securely ingests evidence (like a mounted disk image or memory dump). It generates verifiable MD5 and SHA-256 hashes using a memory-efficient chunking engine to maintain a strict chain of custody.
   
2. **Disk Extraction (`src/disk/`)**:
   The engine crawls the file system to extract high-value forensic artifacts. Currently, it targets the **SYSTEM Registry Hive** and **Prefetch files** (`.pf`), parsing their creation and modification timestamps (MAC times).

3. **Memory Analysis (`src/memory/` & `src/capture/`)**:
   - *Offline Mode:* Uses a wrapper around Volatility 3 to parse pre-captured memory dumps.
   - *Live Mode:* Directly scans the running Windows machine's RAM to find active processes and hidden malicious code.

4. **Correlation & Scoring (`src/correlation/`)**:
   The engine takes the extracted disk artifacts and the analyzed memory processes and merges them into one master timeline. A heuristic threat scorer then evaluates this timeline, assigning risk scores (0-100) based on suspicious behaviors (e.g., `cmd.exe` running from the `Downloads` folder).

5. **Action & Response (`src/response/`)**:
   Finally, the framework spits out two reports: a raw `forensic_report.json` for machine ingestion (SIEMs), and a self-contained `forensic_report.html` dashboard for human analysts to review.

---

## 4. How the Project Works (Low-Level System Architecture)

To truly understand this framework, you have to look at how it interacts with the underlying operating system—specifically during Live RAM Inspection.

### 4.1 Driverless Memory Scanning
Instead of dropping a `.sys` driver onto the disk, the `NativeLiveRAMAnalyzer` (`src/capture/native_ram.py`) leverages Python's `ctypes` library to make direct calls to the Windows API (`kernel32.dll`).

**The workflow looks like this:**
1. **Snapshot:** It calls `CreateToolhelp32Snapshot` to get a list of every process currently running on the system.
2. **Enumerate:** It loops through the snapshot using `Process32First` and `Process32Next`.
3. **Open:** For every process ID (PID), it calls `OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)`.
4. **Query:** It walks the entire memory address space of that process using `VirtualQueryEx`. It looks at the `MEMORY_BASIC_INFORMATION` of every memory page.

### 4.2 Heuristic Threat Detection
While walking the memory pages with `VirtualQueryEx`, the framework looks for specific memory protection combinations that indicate malware.

- **Classic Shellcode Injection (Score: 90):** 
  If a memory page is marked as `PAGE_EXECUTE_READWRITE` (RWX), it means the program can write code into memory and then immediately execute it. This is highly abnormal for legitimate software but is the standard mechanism for malware shellcode injection.
- **Process Hollowing (Score: 60):** 
  If a memory page is marked as `PAGE_EXECUTE_READ` but is unbacked (meaning it doesn't map to a file on disk) and is larger than 1 Megabyte, it likely indicates that a benign process was started, hollowed out, and replaced with a malicious executable payload.

### 4.3 JIT Whitelisting
To prevent false positives, the engine knows that Just-In-Time (JIT) compilers (like the V8 engine in Chrome, or the .NET runtime) legitimately use RWX memory to compile code on the fly. The framework explicitly whitelists processes like `chrome.exe`, `msedge.exe`, and `powershell.exe` to downgrade their risk scores.

### 4.4 Data Normalization
Every piece of data generated by any module must conform strictly to JSON schemas defined in `src/config/data_models.json`. Whether an event came from a Prefetch file on disk or a process in memory, it is normalized into a standard `CorrelatedEvent` object. This strict data contract is what allows the correlation engine to seamlessly merge disk and memory data.

---

## 5. Summary

The Hybrid Forensics Framework is built on the philosophy that incident response tooling should be **stealthy, self-contained, and integrated**. By relying on native Win32 APIs, strict offline constraints, and automated cross-domain correlation, it provides forensic analysts with immediate, high-fidelity insights without being blocked by the environment they are trying to protect.
