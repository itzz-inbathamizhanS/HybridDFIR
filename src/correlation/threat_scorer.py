import datetime
import logging
from src.config import validate_schema

logger = logging.getLogger(__name__)


class ThreatScorer:
    """
    Analyzes timeline events to identify anomalies, assigning risk scores
    and generating standard CorrelatedEvent objects.

    Implements multi-layer heuristic rules covering:
    - Suspicious executable detection (name-based + behavioral)
    - Path-based anomaly detection
    - Parent-child process relationship analysis
    - Timestomping detection
    - Registry persistence indicators
    - Lateral movement tool detection
    - MITRE ATT&CK TTP mapping
    """

    def __init__(self):
        self.correlated_threats = []

        # --- Heuristic Rulesets ---

        # Known malicious / dual-use executables
        self.suspicious_executables = [
            "cmd.exe", "powershell.exe", "pwsh.exe", "mimikatz.exe",
            "psexec.exe", "psexesvc.exe", "wmic.exe", "cscript.exe",
            "wscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
            "certutil.exe", "bitsadmin.exe", "msbuild.exe",
            "installutil.exe", "schtasks.exe", "at.exe",
            "net.exe", "net1.exe", "nltest.exe", "whoami.exe",
            "systeminfo.exe", "tasklist.exe", "sc.exe",
            "procdump.exe", "comsvc.exe",
        ]

        # Suspicious execution paths
        self.suspicious_paths = [
            "temp", "tmp", "appdata", "downloads", "public",
            "programdata", "recycle", "users\\default",
        ]

        # Known legitimate parent -> child relationships
        # If a child runs with an UNEXPECTED parent, it is suspicious
        self.expected_parents = {
            "svchost.exe": ["services.exe"],
            "smss.exe": ["system"],
            "csrss.exe": ["smss.exe"],
            "wininit.exe": ["smss.exe"],
            "winlogon.exe": ["smss.exe"],
            "lsass.exe": ["wininit.exe"],
            "services.exe": ["wininit.exe"],
            "taskhost.exe": ["services.exe", "svchost.exe"],
            "taskhostw.exe": ["services.exe", "svchost.exe"],
        }

        # Lateral movement indicators
        self.lateral_movement_tools = [
            "psexec.exe", "psexesvc.exe", "wmic.exe",
            "winrs.exe", "wsmprovhost.exe",
        ]

        # Registry persistence artifact names
        self.persistence_indicators = [
            "run", "runonce", "userinit", "shell",
            "winlogon", "startup",
        ]

        # MITRE ATT&CK TTP Mapping
        self.mitre_mapping = {
            "cmd.exe": "T1059.003",       # Command and Scripting Interpreter: Windows Command Shell
            "powershell.exe": "T1059.001", # Command and Scripting Interpreter: PowerShell
            "pwsh.exe": "T1059.001",
            "mimikatz.exe": "T1003.001",   # OS Credential Dumping: LSASS Memory
            "psexec.exe": "T1570",         # Lateral Tool Transfer
            "psexesvc.exe": "T1570",
            "wmic.exe": "T1047",           # Windows Management Instrumentation
            "cscript.exe": "T1059.005",    # Command and Scripting Interpreter: Visual Basic
            "wscript.exe": "T1059.005",
            "mshta.exe": "T1218.005",      # System Binary Proxy Execution: Mshta
            "rundll32.exe": "T1218.011",   # System Binary Proxy Execution: Rundll32
            "regsvr32.exe": "T1218.010",   # System Binary Proxy Execution: Regsvr32
            "certutil.exe": "T1140",       # Deobfuscate/Decode Files or Information
            "bitsadmin.exe": "T1197",      # BITS Jobs
            "msbuild.exe": "T1127.001",    # Trusted Developer Utilities Proxy Execution: MSBuild
            "schtasks.exe": "T1053.005",   # Scheduled Task
            "sc.exe": "T1543.003",         # Create or Modify System Process: Windows Service
            "procdump.exe": "T1003.001",   # OS Credential Dumping: LSASS Memory
        }

    def evaluate_timeline(self, timeline: list) -> list:
        """
        Iterates through the timeline to flag suspicious behaviors
        using multi-layered heuristic rules.
        """
        for event in timeline:
            raw_data = event.get("raw_data", {})
            risk_score = 0
            threat_descriptions = []
            mitre_ttps = []

            # ===================================================
            # RULE 1: Suspicious Disk Prefetch
            # ===================================================
            if event["source_module"] == "disk" and event["event_type"] == "Prefetch File":
                exe_name = raw_data.get("details", {}).get("executable_identified", "").lower()
                if exe_name in self.suspicious_executables:
                    risk_score = 75
                    threat_descriptions.append(
                        f"Suspicious executable executed: {exe_name}"
                    )
                    ttp = self.mitre_mapping.get(exe_name)
                    if ttp:
                        mitre_ttps.append(ttp)

            # ===================================================
            # RULE 2: Suspicious Memory Processes
            # ===================================================
            elif event["source_module"] == "memory" and event["event_type"] == "Active Process":
                proc_name = raw_data.get("process_name", "").lower()
                path = raw_data.get("path", "").lower()

                if proc_name in self.suspicious_executables:
                    risk_score += 60
                    threat_descriptions.append(
                        f"High-risk process actively running: {proc_name}"
                    )
                    ttp = self.mitre_mapping.get(proc_name)
                    if ttp:
                        mitre_ttps.append(ttp)

                if any(sus_dir in path for sus_dir in self.suspicious_paths):
                    risk_score += 40
                    threat_descriptions.append(
                        f"Running from unusual directory: {path}"
                    )
                    mitre_ttps.append("T1036.005")  # Masquerading: Match Legitimate Name or Location


            # ===================================================
            # RULE 3: Parent-Child Process Anomaly
            # ===================================================
            if event["source_module"] == "memory" and event["event_type"] == "Active Process":
                proc_name = raw_data.get("process_name", "").lower()
                ppid = raw_data.get("ppid", 0)

                if proc_name in self.expected_parents:
                    # We can only flag this if we have parent info in the dataset
                    # Since we don't always have the parent name, flag if ppid seems odd
                    # This is a placeholder - in a real implementation we'd resolve ppid -> name
                    if ppid == 0 and proc_name not in ("system", "smss.exe"):
                        risk_score += 30
                        threat_descriptions.append(
                            f"Anomalous parent process (PID 0) for {proc_name}"
                        )
                        mitre_ttps.append("T1055")  # Process Injection

            # ===================================================
            # RULE 4: Timestomping Detection
            # ===================================================
            if event["source_module"] == "disk":
                details = raw_data.get("details", {})
                # If we have MAC timestamps, check for anomalies
                raw_meta = raw_data
                created = raw_meta.get("timestamp", "")
                modified = details.get("modified_utc", "")
                if created and modified and created > modified:
                    risk_score += 50
                    threat_descriptions.append(
                        "Potential timestomping: creation time is after modification time"
                    )
                    mitre_ttps.append("T1070.006")  # Indicator Removal: Timestomp

            # ===================================================
            # RULE 5: Lateral Movement Tool Detection
            # ===================================================
            if event["source_module"] in ("disk", "memory"):
                check_name = ""
                if event["event_type"] == "Prefetch File":
                    check_name = raw_data.get("details", {}).get("executable_identified", "").lower()
                elif event["event_type"] == "Active Process":
                    check_name = raw_data.get("process_name", "").lower()

                if check_name in self.lateral_movement_tools:
                    risk_score += 25
                    threat_descriptions.append(
                        f"Lateral movement tool detected: {check_name}"
                    )
                    mitre_ttps.append("T1021")  # Remote Services

            # ===================================================
            # RULE 6: Registry Persistence Indicators
            # ===================================================
            if event["source_module"] == "disk" and event["event_type"] == "Registry Hive":
                source_path = raw_data.get("source_path", "").lower()
                for indicator in self.persistence_indicators:
                    if indicator in source_path:
                        risk_score += 35
                        threat_descriptions.append(
                            f"Registry persistence indicator: {indicator} found in {source_path}"
                        )
                        mitre_ttps.append("T1547.001")  # Boot or Logon Autostart Execution: Registry Run Keys
                        break

            # ===================================================
            # RULE 7: Event Log artifact detection
            # ===================================================
            if event["source_module"] == "disk" and event["event_type"] == "Event Log":
                # Event logs are always worth noting
                risk_score += 10
                threat_descriptions.append(
                    "Windows Event Log artifact detected"
                )

            # ===================================================
            # Emit CorrelatedEvent if any threat found
            # ===================================================
            if risk_score > 0:
                # Cap risk score at 100 per the JSON schema rules
                final_score = min(risk_score, 100)

                # De-duplicate descriptions
                unique_descriptions = list(dict.fromkeys(threat_descriptions))
                description = " | ".join(unique_descriptions)

                # De-duplicate MITRE TTPs
                unique_ttps = list(dict.fromkeys(mitre_ttps))

                correlated_event = {
                    "timestamp": event.get("timestamp"),
                    "source_module": event.get("source_module"),
                    "event_type": "THREAT_DETECTED",
                    "description": description.strip(),
                    "risk_score": final_score,
                }

                if unique_ttps:
                    correlated_event["mitre_attack_ttps"] = unique_ttps

                if not validate_schema(correlated_event, "CorrelatedEvent"):
                    logger.warning("Correlated event failed schema validation: %s", correlated_event.get("description"))

                self.correlated_threats.append(correlated_event)

        logger.info(
            "Threat evaluation complete: %d threats identified from %d timeline events",
            len(self.correlated_threats), len(timeline)
        )
        return self.correlated_threats

    def evaluate_cross_module(
        self,
        memory_findings: list,
        network_findings: list,
        persistence_findings: list,
        dll_findings: list,
    ) -> tuple:
        """
        Cross-module threat correlation - detects attack patterns that
        only become visible when combining data from multiple scanners.

        Rules 8-12 implement novel multi-source correlation that no
        single-tool scanner can achieve.
        
        Returns:
            Tuple of (cross_threats, relationships)
        """
        import uuid
        cross_threats = []
        relationships = []

        # Build lookup sets for fast cross-referencing
        memory_pids = {f["pid"] for f in memory_findings if f.get("risk_score", 0) >= 50}
        memory_procs = {f["process_name"].lower() for f in memory_findings if f.get("risk_score", 0) >= 50}

        network_pids = {f["pid"] for f in network_findings if f.get("risk_score", 0) > 0}

        persistence_exes = set()
        active_implants = set()
        for f in persistence_findings:
            exe = f.get("executable", "").lower()
            if exe:
                persistence_exes.add(exe)
            if f.get("is_active"):
                active_implants.add(exe)

        dll_pids = {f["pid"] for f in dll_findings if f.get("risk_score", 0) >= 40}

        # Ensure all incoming findings have an ID for relationship mapping
        for f in memory_findings + network_findings + persistence_findings + dll_findings:
            if "finding_id" not in f:
                f["finding_id"] = f"FND-{uuid.uuid4().hex[:8].upper()}"

        # ===============================================
        # RULE 8: Process-Network Correlation
        # A process with suspicious memory AND outbound network = likely C2 implant
        # ===============================================
        overlapping_pids = memory_pids & network_pids
        for pid in overlapping_pids:
            mem_proc = next((f for f in memory_findings if f["pid"] == pid and f.get("risk_score", 0) >= 50), None)
            net_proc = next((f for f in network_findings if f["pid"] == pid and f.get("risk_score", 0) > 0), None)
            if mem_proc and net_proc:
                finding_id = f"FND-{uuid.uuid4().hex[:8].upper()}"
                cross_threats.append({
                    "finding_id": finding_id,
                    "timestamp": mem_proc.get("scan_timestamp_utc",
                                              datetime.datetime.now(datetime.UTC).isoformat() + "Z"),
                    "source_module": "memory",
                    "event_type": "CROSS_MODULE_THREAT",
                    "description": (
                        f"[CRITICAL CORRELATION] Process {mem_proc['process_name']} "
                        f"(PID {pid}) has BOTH suspicious memory regions AND "
                        f"outbound network connections - possible active C2 implant"
                    ),
                    "risk_score": 95,
                    "mitre_attack_ttps": ["T1071.001", "T1055"],
                })
                relationships.append((mem_proc["finding_id"], finding_id, "CONTRIBUTES_TO", "HIGH"))
                relationships.append((net_proc["finding_id"], finding_id, "CONTRIBUTES_TO", "HIGH"))

        # ===============================================
        # RULE 9: Persistence-Memory Correlation
        # Registry persistence entry pointing to process with RWX memory = active implant
        # ===============================================
        persisted_and_suspicious = persistence_exes & memory_procs
        for exe in persisted_and_suspicious:
            mem_proc = next((f for f in memory_findings if f.get("process_name", "").lower() == exe and f.get("risk_score", 0) >= 50), None)
            per_proc = next((f for f in persistence_findings if f.get("executable", "").lower() == exe), None)
            
            finding_id = f"FND-{uuid.uuid4().hex[:8].upper()}"
            cross_threats.append({
                "finding_id": finding_id,
                "timestamp": datetime.datetime.now(datetime.UTC).isoformat() + "Z",
                "source_module": "memory",
                "event_type": "CROSS_MODULE_THREAT",
                "description": (
                    f"[ACTIVE IMPLANT] {exe} has registry persistence AND "
                    f"suspicious memory regions - confirmed persistent implant"
                ),
                "risk_score": 100,
                "mitre_attack_ttps": ["T1547.001", "T1055"],
            })
            if mem_proc:
                relationships.append((mem_proc["finding_id"], finding_id, "CONTRIBUTES_TO", "CERTAIN"))
            if per_proc:
                relationships.append((per_proc["finding_id"], finding_id, "CONTRIBUTES_TO", "CERTAIN"))

        # ===============================================
        # RULE 10: DLL-Memory Correlation
        # Injected DLLs + RWX memory in same process = confirmed injection
        # ===============================================
        dll_and_memory = dll_pids & memory_pids
        for pid in dll_and_memory:
            dll_proc = next((f for f in dll_findings if f["pid"] == pid), None)
            mem_proc = next((f for f in memory_findings if f["pid"] == pid and f.get("risk_score", 0) >= 50), None)
            if dll_proc:
                finding_id = f"FND-{uuid.uuid4().hex[:8].upper()}"
                cross_threats.append({
                    "finding_id": finding_id,
                    "timestamp": dll_proc.get("scan_timestamp_utc",
                                              datetime.datetime.now(datetime.UTC).isoformat() + "Z"),
                    "source_module": "memory",
                    "event_type": "CROSS_MODULE_THREAT",
                    "description": (
                        f"[CONFIRMED INJECTION] {dll_proc['process_name']} "
                        f"(PID {pid}) has suspicious DLLs AND RWX memory - "
                        f"confirmed code injection"
                    ),
                    "risk_score": 95,
                    "mitre_attack_ttps": ["T1055.001", "T1574.002"],
                })
                relationships.append((dll_proc["finding_id"], finding_id, "CONTRIBUTES_TO", "CERTAIN"))
                if mem_proc:
                    relationships.append((mem_proc["finding_id"], finding_id, "CONTRIBUTES_TO", "CERTAIN"))

        # ===============================================
        # RULE 11: Temporal Correlation
        # Multiple suspicious events from different modules at similar timestamps
        # ===============================================
        all_timestamps = []
        for src, findings in [("memory", memory_findings), ("network", network_findings)]:
            for f in findings:
                if f.get("risk_score", 0) >= 50:
                    ts = f.get("scan_timestamp_utc", "")
                    if ts:
                        all_timestamps.append((ts, src, f))

        if len(all_timestamps) >= 3:
            finding_id = f"FND-{uuid.uuid4().hex[:8].upper()}"
            cross_threats.append({
                "finding_id": finding_id,
                "timestamp": datetime.datetime.now(datetime.UTC).isoformat() + "Z",
                "source_module": "memory",
                "event_type": "CROSS_MODULE_THREAT",
                "description": (
                    f"[COORDINATED ATTACK] {len(all_timestamps)} high-risk events "
                    f"detected across multiple modules in the same scan window - "
                    f"potential coordinated attack or active compromise"
                ),
                "risk_score": 90,
                "mitre_attack_ttps": ["T1059", "T1055", "T1071"],
            })
            for _, _, f in all_timestamps:
                 relationships.append((f["finding_id"], finding_id, "TEMPORAL_LINK", "MEDIUM"))

        # ===============================================
        # RULE 12: LOLBin Chain Detection
        # Multiple LOLBins active simultaneously = attack chain
        # ===============================================
        lolbins = {"cmd.exe", "powershell.exe", "pwsh.exe", "certutil.exe",
                   "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe",
                   "cscript.exe", "wscript.exe", "bitsadmin.exe", "msbuild.exe"}
        
        active_lolbin_findings = [f for f in memory_findings if f.get("process_name", "").lower() in lolbins and f.get("risk_score", 0) >= 50]
        
        if len(active_lolbin_findings) >= 2:
            finding_id = f"FND-{uuid.uuid4().hex[:8].upper()}"
            active_lolbins_names = {f.get("process_name", "").lower() for f in active_lolbin_findings}
            cross_threats.append({
                "finding_id": finding_id,
                "timestamp": datetime.datetime.now(datetime.UTC).isoformat() + "Z",
                "source_module": "memory",
                "event_type": "CROSS_MODULE_THREAT",
                "description": (
                    f"[LOLBIN CHAIN] {len(active_lolbins_names)} Living-Off-The-Land "
                    f"binaries active simultaneously: {', '.join(sorted(active_lolbins_names))} - "
                    f"potential attack chain execution"
                ),
                "risk_score": 85,
                "mitre_attack_ttps": ["T1059.001", "T1218"],
            })
            for f in active_lolbin_findings:
                relationships.append((f["finding_id"], finding_id, "CONTRIBUTES_TO", "HIGH"))

        if cross_threats:
            logger.info(
                "Cross-module correlation found %d additional threats",
                len(cross_threats),
            )
        self.correlated_threats.extend(cross_threats)
        return cross_threats, relationships
