# Evidence Intake Module

> Module: `src/intake/` — Secure Evidence Ingestion, Validation & Cataloging

---

## 1. Overview

The Evidence Intake module is the first stage of the forensic analysis pipeline. It is responsible for:

- **Validating** that the supplied evidence file exists and is accessible
- **Computing** cryptographic hashes (MD5 + SHA-256) for chain-of-custody verification
- **Generating** a standardized `EvidenceMetadata` payload consumed by all downstream modules

No evidence file contents are modified during intake — the module operates in a strictly **read-only** mode.

---

## 2. Module Structure

```
src/intake/
├── __init__.py          # Exports: EvidenceIntake, calculate_hashes
├── ingest_image.py      # Core intake orchestrator class
└── validator.py          # Chunk-based cryptographic hash engine
```

---

## 3. Core Components

### 3.1 `EvidenceIntake` Class

**File:** `src/intake/ingest_image.py`

The primary entry point for the intake pipeline. Accepts a file path and image type, then executes the full intake workflow.

#### Constructor

```python
EvidenceIntake(file_path: str, image_type: str)
```

| Parameter | Type | Description |
|---|---|---|
| `file_path` | `str` | Path to the forensic image file (`.raw`, `.dd`, `.vmem`, etc.) |
| `image_type` | `str` | Must be `"disk"` or `"memory"` — raises `ValueError` otherwise |

#### `process_evidence() → dict`

Executes the complete intake pipeline:

1. Verifies the evidence file exists on disk (raises `FileNotFoundError` if missing)
2. Reads the file size in bytes
3. Calls `calculate_hashes()` to compute MD5 and SHA-256
4. Constructs and returns the `EvidenceMetadata` dictionary

**Return Value — `EvidenceMetadata` dictionary:**

```json
{
  "evidence_id": "memory_a5f5479a",
  "file_name": "memdump.raw",
  "file_path": "C:\\evidence\\memdump.raw",
  "image_type": "memory",
  "size_bytes": 4294967296,
  "hashes": {
    "md5": "a5f5479a2e3b4c5d6e7f8a9b0c1d2e3f",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb924..."
  },
  "intake_timestamp_utc": "2026-08-23T15:30:00+00:00"
}
```

The `evidence_id` is derived as `<image_type>_<first 8 chars of MD5>`, providing a unique, deterministic identifier for each case.

---

### 3.2 Hash Validator

**File:** `src/intake/validator.py`

#### `calculate_hashes(file_path: str, chunk_size: int = 65536) → dict`

Computes dual cryptographic hashes over the evidence file using a memory-efficient streaming approach.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `file_path` | `str` | — | Absolute or relative path to the evidence file |
| `chunk_size` | `int` | `65536` (64 KB) | Size of each read buffer. Configurable via `settings.HASH_CHUNK_SIZE` |

**Algorithm:**

```
Initialize MD5 and SHA-256 hashlib objects
Open file in binary read mode ("rb")
Loop:
    Read chunk_size bytes
    If empty → break
    Update both hash objects with the chunk
Return { "md5": hex_digest, "sha256": hex_digest }
```

**Error Handling:**

| Exception | Condition |
|---|---|
| `FileNotFoundError` | Evidence file does not exist at the specified path |
| `PermissionError` | Insufficient OS-level read permissions on the file |

The chunk-based approach ensures the module can process multi-gigabyte disk and memory images without exhausting available RAM.

---

## 4. Supported Evidence Formats

The following formats are recognized by the framework (defined in `src/config/settings.py`):

### Disk Image Formats

| Extension | Description |
|---|---|
| `.raw` | Raw disk image (bit-for-bit copy) |
| `.dd` | `dd` utility output |
| `.img` | Generic disk image |
| `.vhd` | Microsoft Virtual Hard Disk |
| `.vmdk` | VMware Virtual Machine Disk |

### Memory Image Formats

| Extension | Description |
|---|---|
| `.raw` | Raw physical memory dump |
| `.vmem` | VMware virtual machine memory snapshot |
| `.dmp` | Windows crash dump / minidump |
| `.sav` | Saved VM state memory snapshot |

---

## 5. Data Schema

The `EvidenceMetadata` output conforms to the JSON Schema defined in `src/config/data_models.json`:

```json
{
  "type": "object",
  "required": [
    "evidence_id", "file_name", "file_path",
    "image_type", "size_bytes", "hashes",
    "intake_timestamp_utc"
  ],
  "properties": {
    "evidence_id": { "type": "string" },
    "file_name": { "type": "string" },
    "file_path": { "type": "string" },
    "image_type": { "type": "string", "enum": ["disk", "memory"] },
    "size_bytes": { "type": "integer" },
    "hashes": {
      "type": "object",
      "required": ["md5", "sha256"],
      "properties": {
        "md5": { "type": "string" },
        "sha256": { "type": "string" }
      }
    },
    "intake_timestamp_utc": { "type": "string", "format": "date-time" }
  }
}
```

---

## 6. Chain-of-Custody Guarantees

| Property | Implementation |
|---|---|
| **Integrity verification** | Dual MD5 + SHA-256 hashing ensures tamper detection |
| **Deterministic IDs** | Evidence ID is derived from the hash — same file always produces the same ID |
| **Timestamp recording** | Intake time is recorded in ISO 8601 UTC format |
| **Read-only operation** | The evidence file is opened in binary read mode only; no bytes are written |
| **Error-on-missing** | Pipeline halts immediately with a `FileNotFoundError` if evidence is missing |

---

## 7. Usage Examples

### Within the Pipeline (via `main.py`)

```python
from src.intake import EvidenceIntake

intake = EvidenceIntake("C:\\evidence\\memdump.raw", "memory")
metadata = intake.process_evidence()
# metadata["evidence_id"] → "memory_a5f5479a"
# metadata["hashes"]["sha256"] → "e3b0c44298fc1c14..."
```

### Standalone Hash Verification

```python
from src.intake import calculate_hashes

hashes = calculate_hashes("C:\\evidence\\disk.dd")
print(f"MD5:    {hashes['md5']}")
print(f"SHA256: {hashes['sha256']}")
```

---

## 8. Test Coverage

The intake module is covered by `tests/test_intake.py`:

| Test Case | Description |
|---|---|
| `test_evidence_intake_success` | Creates a temporary file, runs full intake, asserts correct metadata structure and hash presence |
| `test_evidence_intake_invalid_type` | Verifies that passing an unsupported image type (e.g., `"network"`) raises `ValueError` |

Run tests:
```bash
pytest tests/test_intake.py -v
```

---

*Document version: 1.0 — August 2026*
