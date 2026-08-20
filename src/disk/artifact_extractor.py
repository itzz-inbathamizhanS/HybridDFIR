import os
from .fs_parser import FileSystemParser

class ArtifactExtractor:
    """
    Extracts specific forensic artifacts (Registry, Prefetch) and formats 
    them to strictly match the configured DiskArtifact JSON schema.
    """
    def __init__(self, mount_point: str):
        self.parser = FileSystemParser(mount_point)
        
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
                    "details": {
                        "hive_type": "SYSTEM",
                        "size_bytes": meta.get("size_bytes")
                    }
                })
        return artifacts

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
                        "details": {
                            "executable_identified": executable_name,
                            "size_bytes": meta.get("size_bytes")
                        }
                    })
        return artifacts