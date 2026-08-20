import os
from pathlib import Path

# Air-Gapped Security Directive
ALLOW_NETWORK_ACCESS = False
OFFLINE_MODE = True

# Directory Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = BASE_DIR / "output"
TEMP_DIR = BASE_DIR / "temp"

# Intake Rules
HASH_CHUNK_SIZE = 65536  # 64 KB
SUPPORTED_DISK_FORMATS = [".raw", ".dd", ".img", ".vhd", ".vmdk"]
SUPPORTED_MEMORY_FORMATS = [".raw", ".vmem", ".dmp", ".sav"]

# Ensure standard local directories exist
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)    