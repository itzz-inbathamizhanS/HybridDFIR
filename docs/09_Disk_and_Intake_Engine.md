# Disk and Intake Engine Specifications

While the live memory and network scanners are the "novel" features of this framework, the offline disk and evidence intake engines provide the foundation for traditional post-mortem forensics. This document details their inner workings from zero to all.

## 1. Evidence Intake (`src/intake/`)

When analyzing an offline memory dump (`.raw`) or disk image (`.dd`), establishing a chain of custody is paramount.

### `ingest_image.py` -> `EvidenceIntake`
- **Initialization**: Takes an `image_path` and `image_type` (`"memory"`, `"disk"`, or `"hybrid"`).
- **Validation**: Checks if the file exists and if its size is below `MAX_FILE_SIZE_MB` (50GB limit).
- **Hashing**: Calls `calculate_hashes()` to read the file in 64KB chunks.
- **Evidence ID Generation**: Creates a unique `EVID-YYYYMMDD-HHMMSS` identifier.
- **Output**: Returns an `intake_metadata` dictionary containing the file size, evidence ID, UTC timestamp, and the SHA-256/MD5 hashes.

### `validator.py` -> `calculate_hashes()`
- Reads files in `65536` byte chunks to ensure minimal RAM usage even on 32GB+ memory dumps.
- Computes `SHA-256` and `MD5` simultaneously.

## 2. Disk Artifact Extraction (`src/disk/`)

The disk analysis module is designed to run against a *mounted* disk image. In Windows forensics, `.dd` or `.e01` images are typically mounted as a drive letter (e.g., `E:\`) using Arsenal Image Mounter or FTK Imager.

### `artifact_extractor.py` -> `ArtifactExtractor`
Takes the `mount_point` (e.g., `E:\`) and automatically targets the most critical forensic artifacts.

#### A. System Registry Hives (`extract_system_registry()`)
- **Target Path**: `<mount>\Windows\System32\config\SYSTEM`
- **Methodology**: Uses `fs_parser.py` to read the raw hive file metadata. (Note: True raw hive parsing requires external libraries like `python-registry`; the framework currently tracks the *existence* and MAC timestamps of the hives to detect timestomping).

#### B. Software Registry Hives (`extract_software_registry()`)
- **Target Path**: `<mount>\Windows\System32\config\SOFTWARE`
- Similar tracking to the SYSTEM hive.

#### C. SAM Hive (`extract_sam_registry()`)
- **Target Path**: `<mount>\Windows\System32\config\SAM`
- Tracks the Security Account Manager hive.

#### D. Prefetch Files (`extract_prefetch()`)
- **Target Path**: `<mount>\Windows\Prefetch\*.pf`
- **Methodology**: Iterates over all `.pf` files. Windows creates a `.pf` file every time an executable is run. The filename itself contains the executable name and a path hash (e.g., `CMD.EXE-0A1B2C3D.pf`).
- **Parsing**: Extracts the executable name directly from the filename string split on the `-` character. Passes this to the `ThreatScorer` to identify if tools like `mimikatz.exe` or `psexec.exe` were ever run on the system.

#### E. Windows Event Logs (`extract_event_logs()`)
- **Target Path**: `<mount>\Windows\System32\winevt\Logs\*.evtx`
- **Methodology**: Specifically looks for `Security.evtx` and `System.evtx`.

### `fs_parser.py` -> `FileSystemParser`
A low-level wrapper around Python's `os` and `pathlib` modules designed to interact safely with mounted forensics images without altering MAC (Modified, Accessed, Created) times.

- **`get_file_metadata(file_path)`**: Uses `os.stat` to extract:
  - `size_bytes`
  - `created_utc` (`st_ctime`)
  - `modified_utc` (`st_mtime`)
  - `accessed_utc` (`st_atime`)
- *Threat Correlation*: These MAC timestamps are passed to the `ThreatScorer` (Rule 4). If `created_utc` is later than `modified_utc`, it strongly indicates the malware used "Timestomping" to hide its installation date.
