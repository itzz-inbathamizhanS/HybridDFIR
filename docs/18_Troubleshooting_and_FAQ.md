# 18. Troubleshooting and FAQ

This document outlines common issues encountered when running the Hybrid Forensics Framework and how to resolve them.

---

## 1. "Administrator privileges required" Error

**Symptom:**
When running the dashboard or memory scanner, you receive a `[FAIL] Administrator privileges required` message, and the scan terminates.

**Cause:**
The framework utilizes the Windows `OpenProcess()` API with the `PROCESS_QUERY_INFORMATION` and `PROCESS_VM_READ` access rights. Without Administrator elevation, Windows denies access to other processes (Access Denied / Error 5).

**Solution:**
1. Close your current PowerShell or Command Prompt.
2. Search for "PowerShell" in the Start Menu.
3. Right-click and select **"Run as Administrator"**.
4. Re-navigate to the project directory and run the command again.

---

## 2. UnicodeEncodeError in Terminal

**Symptom:**
The tool crashes with `UnicodeEncodeError: 'charmap' codec can't encode character...` during UI rendering.

**Cause:**
Standard Windows `cmd.exe` and older PowerShell versions default to legacy code pages (like `cp1252`) which cannot render the framework's professional UI tags, box-drawing characters, and progress spinners.

**Solution:**
The framework programmatically attempts to force UTF-8 encoding via `sys.stdout.reconfigure(encoding='utf-8')`. However, if your terminal still fails:
- Run this command in your PowerShell session before executing the framework:
  ```powershell
  $OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding
  ```
- Use the modern **Windows Terminal** application instead of the legacy `conhost.exe`.

---

## 3. Empty Scan Results (0 Threats Found)

**Symptom:**
The dashboard runs successfully, but reports 0 connections, 0 memory regions, or 0 DLLs scanned.

**Cause:**
This can occur if the `ctypes` structures fail to align correctly with your specific Windows build (e.g., mismatched 32-bit vs 64-bit Python), or if an aggressive EDR/Antivirus is blocking the `CreateToolhelp32Snapshot` API call.

**Solution:**
- Ensure you are running a **64-bit version of Python** (`python -c "import platform; print(platform.architecture())"` should say `64bit`).
- Temporarily disable your EDR/AV strictly for the duration of the forensic capture if it is intercepting API calls via user-land hooking.

---

## 4. Where is the HTML Report?

**Symptom:**
You generated an offline disk/memory image analysis but cannot find the HTML report.

**Solution:**
HTML reports are generated exclusively when using the Intake Module on offline evidence (e.g., memory dumps). 
Check the `output/memory_<hash>/` folder for `forensic_report.html`. Live dashboard scans output to the console and save raw `.json` files to `output/`.
