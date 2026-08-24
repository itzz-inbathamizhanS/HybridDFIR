# Hybrid Forensics Framework: Presentation Guide

*This document is structured as a start-to-finish presentation script and guide. It is designed to help you confidently present the Hybrid Forensics Framework to technical audiences, stakeholders, or professors. Each slide/section includes the core concepts to display on-screen, followed by "Speaker Notes" (what you should actually say).*

---

## Slide 1: Title & Introduction
**Visuals:** Project Title ("Hybrid Forensics Framework"), your name, and a tagline: *"Air-Gapped, Driverless Digital Forensics for the Modern Threat Landscape."*

**Speaker Notes:**
> "Hello everyone. Today I am presenting the Hybrid Forensics Framework. When a severe cyberattack occurs—like a ransomware infection or a nation-state breach—incident responders need to extract digital evidence quickly. However, modern security environments are making this harder than ever. This project is a specialized toolkit designed to bypass those modern hurdles by operating entirely offline and utilizing driverless, zero-binary memory acquisition techniques."

---

## Slide 2: The Problem with Traditional Forensics
**Visuals:** Three pillars showing the main challenges:
1. **The EDR Blockade** (Modern security tools block forensic memory drivers)
2. **The Air-Gap Requirement** (Infected machines must be taken offline)
3. **Data Silos** (Disk evidence and memory evidence are analyzed separately)

**Speaker Notes:**
> "Traditionally, to capture what is running in a computer's RAM, investigators use tools that drop a `.sys` kernel driver onto the machine. But today, aggressive Endpoint Detection and Response (EDR) agents and Windows security features like Hypervisor-Enforced Code Integrity (HVCI) instantly block these unknown drivers. We can't capture the memory.
> 
> Furthermore, when a machine is compromised, the very first step is isolating it from the network. If your forensic tool relies on cloud APIs or threat intelligence feeds, it becomes useless. Finally, if you do manage to get the data, disk forensics and memory forensics are usually done in two completely separate silos, leaving the analyst to manually piece together what happened."

---

## Slide 3: The Solution (Project Overview)
**Visuals:** High-level diagram showing: `Live RAM Scanner` + `Disk Extractor` → `Correlation Engine` → `Offline HTML Report`.

**Speaker Notes:**
> "To solve these issues, I built the Hybrid Forensics Framework. It is a completely modular, 100% offline pipeline. 
> 
> Instead of using kernel drivers to capture memory, it uses native Windows APIs to scan live RAM directly from userland, completely bypassing EDR driver blocks. It also extracts critical forensic artifacts from the disk. But most importantly, it takes the disk evidence and the memory evidence, feeds them into a Correlation Engine, and automatically merges them into a single, chronologically ordered timeline."

---

## Slide 4: Zero-Binary Memory Scanning (Deep Dive)
**Visuals:** Diagram showing Python `ctypes` calling `kernel32.dll` (`CreateToolhelp32Snapshot`, `VirtualQueryEx`, `OpenProcess`).

**Speaker Notes:**
> "Let's look under the hood at the live memory scanner. This is the most technically complex part of the framework. It is 'zero-binary', meaning we don't compile and drop any sketchy C++ executables or kernel drivers onto the target machine.
> 
> Instead, we use Python's `ctypes` library to hook directly into native Windows APIs. We take a snapshot of all running processes using `CreateToolhelp32Snapshot`, open a read-handle to each process, and then use `VirtualQueryEx` to walk through every single page of memory allocated to that program."

---

## Slide 5: Heuristic Threat Detection
**Visuals:** Table showing Heuristic Rules:
- `RWX_SHELLCODE_INJECTION` (PAGE_EXECUTE_READWRITE) → Score 90
- `LARGE_PRIVATE_EXECUTABLE` (Process Hollowing) → Score 60
- `JIT / AV Whitelisting` → Score downgraded to 10

**Speaker Notes:**
> "While we are walking those memory pages, what are we looking for? We are looking for malicious memory protections. 
> 
> For example, if a region of memory is marked as `PAGE_EXECUTE_READWRITE`, that means a program can write data into memory and immediately execute it. While this is rare for normal software, it is the exact mechanism malware uses to inject malicious shellcode. We flag this immediately with a Risk Score of 90.
> 
> Of course, legitimate programs like Google Chrome's V8 JavaScript engine or the .NET runtime do this legitimately for Just-In-Time (JIT) compiling. Our framework intelligently whitelists known JIT compilers and Antivirus products to drastically reduce false positives."

---

## Slide 6: Disk Artifact Extraction
**Visuals:** Icons representing the Windows Registry and Prefetch files.

**Speaker Notes:**
> "While the memory scanner looks for active threats, the disk extractor looks for historical evidence. It parses the file system to locate the Windows SYSTEM Registry hive, giving us system configuration states, and Windows Prefetch files (`.pf`). 
> 
> Prefetch files are incredibly valuable because Windows creates them every time an application is run to speed up future load times. By extracting these, we can prove that a specific executable ran on the system, even if the attacker already deleted the actual file."

---

## Slide 7: The Correlation Engine
**Visuals:** A funnel pulling "Memory Data" and "Disk Data" into a unified chronological list (Timeline), then hitting a "Heuristic Ruleset".

**Speaker Notes:**
> "Once we have the disk artifacts and the memory processes, they are passed to the Correlation Engine. Because every module in this framework enforces strict JSON schemas, the engine can seamlessly merge these entirely different data types into one chronological timeline.
> 
> The engine then evaluates this timeline. If it sees a Prefetch file indicating `powershell.exe` was executed from a suspicious directory like the `Downloads` folder, and then correlates that with an active process running in memory, it automatically escalates the threat score."

---

## Slide 8: Automated Offline Reporting
**Visuals:** Screenshots of the output folder (`forensic_report.json` and the HTML dashboard).

**Speaker Notes:**
> "Finally, the framework needs to output this data so an analyst can act on it. Remember, we are air-gapped, so we cannot rely on cloud dashboards.
> 
> The Action Response module generates two files locally: a structured JSON report designed to be ingested by enterprise SIEMs (Security Information and Event Management systems), and a self-contained, color-coded HTML dashboard. The HTML file has all its CSS embedded directly inside it, meaning it renders perfectly and beautifully on an isolated machine with no internet connection."

---

## Slide 9: Conclusion & Future Work
**Visuals:** Summary bullet points and Roadmap (MFT parsing, Event Logs, Linux support).

**Speaker Notes:**
> "In conclusion, the Hybrid Forensics Framework provides incident responders with a stealthy, driverless, and fully offline toolkit that breaks down the silos between disk and memory forensics. 
> 
> Looking forward, I plan to expand the disk analysis to include NTFS Master File Table ($MFT) parsing and deep Windows Event Log correlation, as well as porting the memory scanner to support Linux environments.
> 
> Thank you for your time. I'd be happy to answer any questions."

---

## Q&A Prep (Anticipated Questions)

**Q: If you aren't using a kernel driver, how do you read memory protected by the OS?**
*A: We operate in user-mode using elevated Administrator privileges. We can inspect the memory of any standard user or system process. We cannot inspect the memory of the Windows Kernel itself or Protected Process Light (PPL) processes (like Windows Defender), but 95% of malware operates in standard user-space where our tool has full visibility.*

**Q: Why use Python for this instead of C or C++?**
*A: Python allows for rapid development, extremely fast JSON data manipulation, and easy cross-platform adaptability. By using `ctypes`, we get the execution speed of native C structures while keeping the high-level orchestration benefits of Python.*

**Q: How does this tool handle large RAM sizes (e.g., 64GB)?**
*A: The Live RAM scanner is highly optimized. It doesn't dump the full 64GB to disk. It queries the metadata of the memory pages first, which takes milliseconds. It only extracts or flags the specific memory pages that violate our heuristic rules.*
