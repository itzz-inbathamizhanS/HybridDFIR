# Hybrid Forensics Framework - Project State & Handoff Summary

## 📌 Context
This document is designed for an LLM/Chatbot to quickly understand the current state, architecture, and recent changes made to the "Hybrid Forensics Framework" project. The user is preparing for the **SIH Hackathon** and requires the framework to perform live memory and disk forensics on Windows without requiring kernel drivers.

## 📁 Exported Files in this Directory
1. `transcript.jsonl` - The complete raw chat history JSONL dump between the user and the previous AI assistant.
2. `implementation_plan.md` - The original planned architecture and phases for the hackathon deliverables.
3. `task.md` - The checklist of tasks completed during this session.
4. `walkthrough.md` - A high-level summary of the features implemented in the codebase.
5. `HANDOFF_SUMMARY.md` - (This file) A structured summary of the current working state.

---

## 🚀 Current Working State (What is Completed)
All phases of the SIH hackathon requirements have been **completed and are fully functional**.

### 1. Framework Architecture
- **Location:** `A:\hybrid-forensics-framework`
- **Language:** Python 3.12+ (Virtual Environment at `venv\`)
- **Key Modules:**
  - `src/capture/native_ram.py`: Performs zero-binary, driverless live RAM acquisition using `ctypes` and Win32 APIs (`CreateToolhelp32Snapshot`, `VirtualQueryEx`, `ReadProcessMemory`).
  - `src/correlation/timeline_builder.py`: Converts memory and disk findings into timeline events and saves them to JSON.
  - `src/correlation/threat_scorer.py`: Applies MITRE ATT&CK heuristics to assign risk scores to suspicious memory regions.
  - `src/main.py`: The main entry point featuring both an Interactive REPL and a CLI Flag interface.

### 2. Live Memory Scanner (`/scan`)
The live memory scanner is the core feature built for the demo. It evaluates every running process's memory regions against heuristics (e.g., RWX Shellcode Injection, Large Private Executable, Process Hollowing).

**Recent Fixes & Features Added:**
- **Show All Processes:** The scanner now displays a massive table of *every* active process on the system. Processes with no suspicious memory are explicitly listed as `CLEAN_PROCESS` with a Risk Score of `0` in dim green.
- **Critical Filter:** Added a `--critical` flag (`/scan --critical`) to filter out the noise and only show memory regions with a Risk Score >= 50.
- **False Positive Whitelisting:** Standard Dell (`Dell.TechHub.exe`), Intel (`IntelAudioService`), and Lavasoft Adware background services natively allocate RWX memory, which was causing 200+ false-positive "Critical Shellcode Injection" alerts. These processes have been explicitly added to `KNOWN_JIT_PROCESSES` and `KNOWN_AV_PROCESSES` inside `native_ram.py`, suppressing them to a Risk Score of `10` (Low Risk / JIT).
- **Import Error Fixed:** Fixed a `ModuleNotFoundError` where `TimelineBuilder` was imported from `src.timeline` instead of `src.correlation`.

### 3. How to Run the Tool
The user has been provided with "All-in-One" PowerShell commands to quickly launch the tool during their presentation without dropping into the interactive shell.

**To run the full visual memory scan (shows all clean & flagged processes):**
```powershell
cd A:\hybrid-forensics-framework; .\venv\Scripts\Activate.ps1; python src\main.py --scan
```

**To filter noise and show only critical threats:**
```powershell
cd A:\hybrid-forensics-framework; .\venv\Scripts\Activate.ps1; python src\main.py --scan --critical
```

## ⚠️ Known Quicksand / Rules for the Next AI
If the user asks for further modifications, please adhere to the following rules established during this session:
1. **Do not modify the core Win32 API logic in `native_ram.py`** unless absolutely necessary. The memory extraction (`VirtualQueryEx`) is highly sensitive to pointer sizes and Windows permissions.
2. **Virtual Environment:** If the user gets `No Python at 'C:\Users\...'`, it means they moved the folder and broke the `venv` hardlinks. The `venv` must be deleted and recreated (`python -m venv venv`, `pip install -r requirements.txt`, `pip install jsonschema`).
3. **Dependencies:** The application strictly relies on `rich` for the terminal UI and `jsonschema` for validating the `data_models.json` definitions. No heavy machine-learning libraries or external drivers (like WinPmem) should be made mandatory, as the goal is a lightweight, zero-binary execution.
