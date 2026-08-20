import os
import datetime

class FileSystemParser:
    """
    Parses mounted disk images or local directory structures to locate 
    forensic artifacts and extract MAC timestamps.
    """
    def __init__(self, mount_point: str):
        """
        Args:
            mount_point (str): The root path of the mounted disk image or drive.
        """
        self.mount_point = mount_point
        if not os.path.exists(self.mount_point):
            raise FileNotFoundError(f"CRITICAL: Mount point not found at {self.mount_point}")

    def locate_file(self, target_filename: str) -> list:
        """
        Recursively searches for a specific file across the mounted file system.
        """
        matches = []
        for root, _, files in os.walk(self.mount_point):
            if target_filename in files:
                full_path = os.path.join(root, target_filename)
                matches.append(full_path)
        return matches

    def get_file_metadata(self, file_path: str) -> dict:
        """
        Extracts MAC (Modified, Accessed, Created) times for a file securely.
        """
        if not os.path.exists(file_path):
            return {}
        
        stats = os.stat(file_path)
        return {
            "created_utc": datetime.datetime.fromtimestamp(stats.st_ctime, tz=datetime.timezone.utc).isoformat(),
            "modified_utc": datetime.datetime.fromtimestamp(stats.st_mtime, tz=datetime.timezone.utc).isoformat(),
            "accessed_utc": datetime.datetime.fromtimestamp(stats.st_atime, tz=datetime.timezone.utc).isoformat(),
            "size_bytes": stats.st_size
        }