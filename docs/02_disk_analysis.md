# Disk Analysis Module

> Module: `src/disk/` — File System Parsing & Artifact Extraction

---

## 1. Overview

The Disk Analysis module is responsible for extracting forensically significant artifacts from mounted disk images or local file systems. It produces structured `DiskArtifact` objects that feed into the correlation engine's timeline builder.

The module operates in two layers:

1. **File System Parser** — Low-level directory traversal and MAC timestamp extraction
2. **Artifact Extractor** — High-level extraction of specific forensic artifacts (Registry hives, Prefetch files)

---

## 2. Module Structure

```
src/disk/
├── __init__.py              # Exports: FileSystemParser, ArtifactExtractor
├── fs_parser.py             # File system walking and metadata extraction
└── artifact_extractor.py    # Registry hive and Prefetch file extraction
```

---

## 3. Core Components

### 3.1 `FileSystemParser` Class

**File:** `src/disk/fs_parser.py`

The foundational layer that provides file system traversal and metadata extraction capabilities.

#### Constructor

```python
FileSystemParser(mount_point: str)
```

| Parameter | Type | Description |
|---|---|---|
| `mount_point` | `str` | Root path of the mounted disk image or drive (e.g., `E:\` or `/mnt/evidence`) |

Raises `FileNotFoundError` if the mount point does not exist.

#### Methods

##### `locate_file(target_filename: str) → list`

Recursively searches the entire mounted file system for files matching the given filename.

```python
parser = FileSystemParser("E:\\")
system_hives = parser.locate_file("SYSTEM")
# Returns: ["E:\\Windows\\System32\\config\\SYSTEM", ...]
```

Uses `os.walk()` to traverse all directories from the mount point root. Returns a list of absolute paths to every matching file.

##### `get_file_metadata(file_path: str) → dict`

Extracts MAC (Modified, Accessed, Created) timestamps for a single file using `os.stat()`.

**Return Value:**

```json
{
  "created_utc": "2026-01-15T10:30:00+00:00",
  "modified_utc": "2026-08-20T14:22:15+00:00",
  "accessed_utc": "2026-08-23T09:45:30+00:00",
  "size_bytes": 16777216
}
```

All timestamps are converted to ISO 8601 UTC format using `datetime.timezone.utc`. Returns an empty dictionary if the file does not exist.

---

### 3.2 `ArtifactExtractor` Class

**File:** `src/disk/artifact_extractor.py`

High-level extraction engine that targets specific forensic artifacts and formats them to match the `DiskArtifact` JSON schema.

#### Constructor

```python
ArtifactExtractor(mount_point: str)
```

Internally creates a `FileSystemParser` instance for the given mount point.

#### Methods

##### `extract_system_registry() → list`

Locates and extracts metadata for Windows SYSTEM registry hives.

**Search Logic:**

1. Uses `FileSystemParser.locate_file("SYSTEM")` to find all files named `SYSTEM`
2. Filters results to only include files in the expected path containing both `system32` and `config` (case-insensitive)
3. Extracts MAC timestamps for each valid hive

**Output — `DiskArtifact` format:**

```json
{
  "artifact_type": "Registry Hive",
  "source_path": "E:\\Windows\\System32\\config\\SYSTEM",
  "timestamp": "2026-08-20T14:22:15+00:00",
  "details": {
    "hive_type": "SYSTEM",
    "size_bytes": 16777216
  }
}
```

##### `extract_prefetch() → list`

Locates and parses Windows Prefetch files (`.pf`) to identify previously executed applications.

**Search Logic:**

1. Constructs the standard Prefetch path: `<mount_point>/Windows/Prefetch/`
2. Lists all `.pf` files in that directory
3. Parses the executable name from the Prefetch filename format: `APPNAME-HASH.pf` → `APPNAME.exe`
4. Extracts MAC timestamps for each file

**Output — `DiskArtifact` format:**

```json
{
  "artifact_type": "Prefetch File",
  "source_path": "E:\\Windows\\Prefetch\\CMD.EXE-4A81B364.pf",
  "timestamp": "2026-08-22T11:05:00+00:00",
  "details": {
    "executable_identified": "CMD.exe",
    "size_bytes": 32768
  }
}
```

##### `extract_all_artifacts() → list`

Convenience method that calls both `extract_system_registry()` and `extract_prefetch()`, returning a combined list of all extracted artifacts.

---

## 4. Data Schema

All output conforms to the `DiskArtifact` schema defined in `src/config/data_models.json`:

```json
{
  "type": "object",
  "required": ["artifact_type", "source_path", "timestamp", "details"],
  "properties": {
    "artifact_type": { "type": "string" },
    "source_path": { "type": "string" },
    "timestamp": { "type": "string" },
    "details": { "type": "object" }
  }
}
```

---

## 5. Artifact Types Reference

| Artifact Type | Source | Forensic Value |
|---|---|---|
| **Registry Hive** (SYSTEM) | `Windows\System32\config\SYSTEM` | System configuration, mounted devices, services, network settings |
| **Prefetch File** | `Windows\Prefetch\*.pf` | Evidence of application execution — name, execution count, timestamps |

---

## 6. Downstream Integration

The `DiskArtifact` list produced by this module flows into two downstream consumers:

```
ArtifactExtractor.extract_all_artifacts()
        │
        ├──→ TimelineBuilder.ingest_disk_artifacts()
        │    Merges disk events into the chronological timeline
        │
        └──→ ThreatScorer.evaluate_timeline()
             Checks for suspicious executables in Prefetch data
```

The `ThreatScorer` specifically examines Prefetch artifacts for known suspicious executables (`cmd.exe`, `powershell.exe`, `mimikatz.exe`, `psexec.exe`), flagging them with a risk score of 75.

---

## 7. Usage Example

```python
from src.disk import ArtifactExtractor

# Point to the mounted evidence volume
extractor = ArtifactExtractor("E:\\")

# Extract all forensic artifacts
artifacts = extractor.extract_all_artifacts()

for artifact in artifacts:
    print(f"[{artifact['artifact_type']}] {artifact['source_path']}")
    print(f"  Timestamp: {artifact['timestamp']}")
    print(f"  Details:   {artifact['details']}")
```

---

## 8. Limitations & Future Work

| Current Limitation | Planned Enhancement |
|---|---|
| Only SYSTEM hive is targeted | Add SAM, SOFTWARE, SECURITY, NTUSER.DAT hive parsing |
| Prefetch filename parsing only | Deep Prefetch binary parsing for execution counts and referenced DLLs |
| No NTFS-specific parsing | MFT ($MFT) timeline extraction and USN journal parsing |
| No event log extraction | Windows Event Log (`.evtx`) parsing and correlation |

---

*Document version: 1.0 — August 2026*
