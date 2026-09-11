# HybridDFIR: Core Forensics Concepts & Attack Vectors

This document explains the specific attack techniques and forensic concepts that the HybridDFIR framework actively hunts for. It is designed to help team members understand *why* we scan for certain things like "Persistence" or "DLLs", *how* attackers use them, and *how* HybridDFIR detects them.

---

## 1. Persistence Mechanisms

### What is it?
Persistence is the technique attackers use to maintain access to a compromised system across restarts, changed credentials, and other interruptions. If an attacker hacks a computer but doesn't install a persistence mechanism, they will lose access as soon as the user reboots the machine.

### How do attackers use it?
Attackers achieve persistence by placing malicious code in locations where the Windows operating system automatically executes code on boot or user login. While attackers can use many methods (like Scheduled Tasks or malicious Services), the most common and historically abused method is via the Windows Registry.
- **Registry Run Keys:** (e.g., `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`). Any program listed here starts automatically.

### Why do we need to hunt for it?
Finding persistence is critical because it tells investigators exactly *how* the malware survives. Removing a malicious file from the desktop isn't enough; if the persistence mechanism (like a Registry key) isn't deleted, the malware will simply redownload and execute itself on the next reboot. 

### How HybridDFIR handles it:
*Note: HybridDFIR currently focuses specifically on Registry-based persistence.* 
The tool features a dedicated Registry Persistence Hunter (`/persistence` in the dashboard). It automatically parses the Windows Registry hives and flags suspicious entries—for example, a Run key pointing to a random executable in the `AppData\Temp` folder, which is highly abnormal for legitimate software.

---

## 2. DLL Injection and Hollowing

### What is a DLL?
A Dynamic Link Library (DLL) is a file containing code and data that can be used by multiple programs at the same time. For example, Windows has DLLs that handle drawing windows or connecting to the internet. Legitimate programs load these DLLs into their memory to use those functions.

### How do attackers use it? (Injection & Hollowing)
Attackers want to hide their malicious activity. If they run a program called `virus.exe`, the user or antivirus will see it easily in Task Manager.
Instead, they use advanced techniques:
- **DLL Injection:** The attacker forces a legitimate, running process (like `explorer.exe` or `notepad.exe`) to load a malicious DLL. The malicious code now runs *inside* the memory space of a trusted program, bypassing firewalls and hiding from simple process lists.
- **Process Hollowing:** The attacker starts a legitimate program in a suspended state, "hollows out" (unmaps) the legitimate code from memory, and replaces it with malicious code before letting the process run. To Windows, it looks like a normal program, but it's actually malware wearing the legitimate program like a skin.

### Why do we need to hunt for it?
Because these techniques execute purely in memory and hide behind trusted system processes, traditional disk-based antivirus scanners often cannot see them. If you only look at the hard drive, you will completely miss an injected attack.

### How HybridDFIR handles it:
The tool uses the `/dllinspect` and Memory Inspection modules. By wrapping Volatility 3 and scanning live RAM, HybridDFIR can look *inside* the memory space of running processes. It looks for anomalies like memory regions marked as "Read-Write-Execute" (RWX), which is highly unusual for legitimate code but required for injected malware.

---

## 3. Network Connection Intelligence

### What is it?
Network connection intelligence involves analyzing the active network sockets (connections) on a machine to see what IP addresses and ports the computer is communicating with.

### How do attackers use it?
Once malware infects a machine, it rarely operates in isolation. It almost always needs to "phone home" to a Command and Control (C2) server. This server gives the malware instructions (e.g., "encrypt these files", "download this payload") and receives stolen data.

### Why do we need to hunt for it?
Tracking network connections allows investigators to find the "puppeteer" controlling the malware. Identifying the C2 server's IP address allows the security team to block it at the firewall, immediately neutralizing the attack across the entire company, even if the malware is still on the computers. It also helps identify data exfiltration (e.g., seeing a massive upload to an unknown Russian IP address).

### How HybridDFIR handles it:
The `/network` module captures the active routing tables and socket connections from memory. It cross-references the running processes with their network connections. The Threat Scorer then evaluates this. For example, `chrome.exe` making a connection over port 443 (HTTPS) is normal. But if a native system tool like `calc.exe` or `svchost.exe` makes a connection to a non-standard port or an unknown IP, HybridDFIR immediately flags it as a critical threat.

---

## 4. Why an Integrated Approach is Necessary

In a real attack, these elements are chained together:
1. An attacker gains access and injects malicious code into memory (**DLL Injection**).
2. The injected code reaches out to a server to download instructions (**Network Connection**).
3. The instructions tell the malware to create a registry key so it survives a reboot (**Persistence**).

By bringing Memory, Disk, and Network analysis into one timeline, HybridDFIR allows an investigator to see this entire chain of events unfold automatically, rather than manually hunting through three different specialized tools.
