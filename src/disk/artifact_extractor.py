import os
import logging
from .fs_parser import FileSystemParser

logger = logging.getLogger(__name__)


class ArtifactExtractor:
    """
    Extracts specific forensic artifacts from mounted disk images and formats
    them to strictly match the configured DiskArtifact JSON schema.

    Supported artifact types:
    - Registry Hives: SYSTEM, SAM, SOFTWARE, SECURITY, NTUSER.DAT
    - Prefetch Files (.pf)
    - Windows Event Logs (.evtx)
    - Amcache.hve (application execution evidence)
    """

    def __init__(self, mount_point: str):
        self.parser = FileSystemParser(mount_point)

    # ----------------------------------------------
    #  Registry Hives
    # ----------------------------------------------

    def extract_system_registry(self) -> list:
        """Locates and extracts metadata for the Windows SYSTEM registry hive."""
        artifacts = []
        # Target the SYSTEM hive
        system_hives = self.parser.locate_file("SYSTEM")

        for hive in system_hives:
            # Validate it is located in the expected System32\config path
            if "config" in hive.lower() and "system32" in hive.lower():
                meta = self.parser.get_file_metadata(hive)
                artifacts.append({
                    "artifact_type": "Registry Hive",
                    "source_path": hive,
                    "timestamp": meta.get("modified_utc", "UNKNOWN"),
                    "details": { "extraction_status": "METADATA_ONLY",
                        "hive_type": "SYSTEM",
                        "size_bytes": meta.get("size_bytes"),
                        "forensic_value": "System configuration, mounted devices, services, network settings"
                    }
                })
        logger.info("Extracted %d SYSTEM registry hive(s)", len(artifacts))
        return artifacts

    def extract_sam_registry(self) -> list:
        """Locates and extracts metadata for the Windows SAM registry hive."""
        artifacts = []
        sam_hives = self.parser.locate_file("SAM")

        for hive in sam_hives:
            if "config" in hive.lower() and "system32" in hive.lower():
                meta = self.parser.get_file_metadata(hive)
                artifacts.append({
                    "artifact_type": "Registry Hive",
                    "source_path": hive,
                    "timestamp": meta.get("modified_utc", "UNKNOWN"),
                    "details": { "extraction_status": "METADATA_ONLY",
                        "hive_type": "SAM",
                        "size_bytes": meta.get("size_bytes"),
                        "forensic_value": "User accounts, password hashes, login history"
                    }
                })
        logger.info("Extracted %d SAM registry hive(s)", len(artifacts))
        return artifacts

    def extract_software_registry(self) -> list:
        """Locates and extracts metadata for the Windows SOFTWARE registry hive."""
        artifacts = []
        software_hives = self.parser.locate_file("SOFTWARE")

        for hive in software_hives:
            if "config" in hive.lower() and "system32" in hive.lower():
                meta = self.parser.get_file_metadata(hive)
                artifacts.append({
                    "artifact_type": "Registry Hive",
                    "source_path": hive,
                    "timestamp": meta.get("modified_utc", "UNKNOWN"),
                    "details": { "extraction_status": "METADATA_ONLY",
                        "hive_type": "SOFTWARE",
                        "size_bytes": meta.get("size_bytes"),
                        "forensic_value": "Installed programs, autoruns, OS version, uninstall entries"
                    }
                })
        logger.info("Extracted %d SOFTWARE registry hive(s)", len(artifacts))
        return artifacts

    def extract_security_registry(self) -> list:
        """Locates and extracts metadata for the Windows SECURITY registry hive."""
        artifacts = []
        security_hives = self.parser.locate_file("SECURITY")

        for hive in security_hives:
            if "config" in hive.lower() and "system32" in hive.lower():
                meta = self.parser.get_file_metadata(hive)
                artifacts.append({
                    "artifact_type": "Registry Hive",
                    "source_path": hive,
                    "timestamp": meta.get("modified_utc", "UNKNOWN"),
                    "details": { "extraction_status": "METADATA_ONLY",
                        "hive_type": "SECURITY",
                        "size_bytes": meta.get("size_bytes"),
                        "forensic_value": "Security policies, audit settings, cached credentials"
                    }
                })
        logger.info("Extracted %d SECURITY registry hive(s)", len(artifacts))
        return artifacts

    def extract_ntuser_registry(self) -> list:
        """Locates and extracts metadata for NTUSER.DAT files (per-user hives)."""
        artifacts = []
        ntuser_hives = self.parser.locate_file("NTUSER.DAT")

        for hive in ntuser_hives:
            # NTUSER.DAT is typically in Users\<username>\ directories
            if "users" in hive.lower():
                meta = self.parser.get_file_metadata(hive)
                # Extract the username from the path
                parts = hive.replace("\\", "/").split("/")
                username = "UNKNOWN"
                for i, part in enumerate(parts):
                    if part.lower() == "users" and i + 1 < len(parts):
                        username = parts[i + 1]
                        break

                artifacts.append({
                    "artifact_type": "Registry Hive",
                    "source_path": hive,
                    "timestamp": meta.get("modified_utc", "UNKNOWN"),
                    "details": { "extraction_status": "METADATA_ONLY",
                        "hive_type": "NTUSER.DAT",
                        "username": username,
                        "size_bytes": meta.get("size_bytes"),
                        "forensic_value": "Per-user settings, recent files, typed URLs, USB history"
                    }
                })
        logger.info("Extracted %d NTUSER.DAT hive(s)", len(artifacts))
        return artifacts

    # ----------------------------------------------
    #  Prefetch Files
    # ----------------------------------------------

    def extract_prefetch(self) -> list:
        """Locates Windows Prefetch files to identify executed applications."""
        artifacts = []
        # Construct standard Prefetch path relative to the mount point
        prefetch_dir = os.path.join(self.parser.mount_point, "Windows", "Prefetch")

        if os.path.exists(prefetch_dir):
            for file in os.listdir(prefetch_dir):
                if file.endswith(".pf"):
                    full_path = os.path.join(prefetch_dir, file)
                    meta = self.parser.get_file_metadata(full_path)

                    # Prefetch files are named APPNAME-HASH.pf
                    executable_name = file.split('-')[0] + ".exe"

                    artifacts.append({
                        "artifact_type": "Prefetch File",
                        "source_path": full_path,
                        "timestamp": meta.get("created_utc", "UNKNOWN"),
                        "details": { "extraction_status": "METADATA_ONLY",
                            "executable_identified": executable_name,
                            "size_bytes": meta.get("size_bytes"),
                            "forensic_value": "Evidence of application execution"
                        }
                    })
        logger.info("Extracted %d Prefetch file(s)", len(artifacts))
        return artifacts

    # ----------------------------------------------
    #  Windows Event Logs
    # ----------------------------------------------

    def extract_event_logs(self) -> list:
        """Locates Windows Event Log (.evtx) files and extracts metadata."""
        artifacts = []
        evtx_dir = os.path.join(
            self.parser.mount_point, "Windows", "System32", "winevt", "Logs"
        )

        # Key event logs for forensic analysis
        priority_logs = {
            "Security.evtx": "Authentication, privilege escalation, audit events",
            "System.evtx": "Service changes, driver loads, system errors",
            "Application.evtx": "Application crashes, installation events",
            "Microsoft-Windows-PowerShell%4Operational.evtx": "PowerShell command execution",
            "Microsoft-Windows-Sysmon%4Operational.evtx": "Sysmon process/network monitoring",
            "Microsoft-Windows-TaskScheduler%4Operational.evtx": "Scheduled task activity",
            "Microsoft-Windows-Windows Defender%4Operational.evtx": "AV detection events",
            "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx": "RDP sessions",
        }

        if os.path.exists(evtx_dir):
            for file in os.listdir(evtx_dir):
                if file.endswith(".evtx"):
                    full_path = os.path.join(evtx_dir, file)
                    meta = self.parser.get_file_metadata(full_path)

                    forensic_value = priority_logs.get(
                        file,
                        "Windows event log"
                    )
                    is_priority = file in priority_logs

                    artifacts.append({
                        "artifact_type": "Event Log",
                        "source_path": full_path,
                        "timestamp": meta.get("modified_utc", "UNKNOWN"),
                        "details": { "extraction_status": "METADATA_ONLY",
                            "log_name": file,
                            "size_bytes": meta.get("size_bytes"),
                            "is_priority": is_priority,
                            "forensic_value": forensic_value
                        }
                    })
        logger.info("Extracted %d Event Log file(s)", len(artifacts))
        return artifacts

    # ----------------------------------------------
    #  Amcache.hve
    # ----------------------------------------------

    def extract_amcache(self) -> list:
        """Locates and extracts metadata for Amcache.hve (app execution evidence)."""
        artifacts = []
        amcache_files = self.parser.locate_file("Amcache.hve")

        for amcache in amcache_files:
            if "appcompat" in amcache.lower():
                meta = self.parser.get_file_metadata(amcache)
                artifacts.append({
                    "artifact_type": "Amcache",
                    "source_path": amcache,
                    "timestamp": meta.get("modified_utc", "UNKNOWN"),
                    "details": { "extraction_status": "METADATA_ONLY",
                        "size_bytes": meta.get("size_bytes"),
                        "forensic_value": "Application execution history, SHA1 hashes, install timestamps"
                    }
                })
        logger.info("Extracted %d Amcache artifact(s)", len(artifacts))
        return artifacts

    # ----------------------------------------------
    #  Master Extraction
    # ----------------------------------------------

    def extract_all_artifacts(self) -> list:
        """Convenience method to extract all supported artifacts."""
        artifacts = []

        # Registry Hives
        artifacts.extend(self.extract_system_registry())
        artifacts.extend(self.extract_sam_registry())
        artifacts.extend(self.extract_software_registry())
        artifacts.extend(self.extract_security_registry())
        artifacts.extend(self.extract_ntuser_registry())

        # Execution Evidence
        artifacts.extend(self.extract_prefetch())
        artifacts.extend(self.extract_amcache())

        # Event Logs
        artifacts.extend(self.extract_event_logs())

        logger.info("Total artifacts extracted: %d", len(artifacts))
        return artifacts
