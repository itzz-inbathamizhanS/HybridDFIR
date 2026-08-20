import hashlib
import os

def calculate_hashes(file_path: str, chunk_size: int = 65536) -> dict:
    """
    Calculates MD5 and SHA256 hashes for a given evidence file.
    Reads in chunks to handle massive disk/memory images without memory exhaustion.
    
    Args:
        file_path (str): The absolute or relative path to the evidence file.
        chunk_size (int): Size of chunks to read into memory (default 64KB).
        
    Returns:
        dict: A dictionary containing the md5 and sha256 hex digests.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"CRITICAL: Evidence file not found at {file_path}")

    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            # Read the file iteratively in chunks
            for chunk in iter(lambda: f.read(chunk_size), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
    except PermissionError:
        raise PermissionError(f"CRITICAL: Insufficient permissions to read {file_path}")

    return {
        "md5": md5_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest()
    }