from typing import TypedDict, Literal, Dict, Any, Union

class EvidenceHashes(TypedDict):
    md5: str
    sha256: str

class EvidenceMetadata(TypedDict):
    evidence_id: str
    file_name: str
    file_path: str
    image_type: Literal["disk", "memory"]
    size_bytes: int
    hashes: EvidenceHashes
    intake_timestamp_utc: str

class DiskArtifactDetails(TypedDict, total=False):
    hive_type: str
    size_bytes: int
    executable_identified: str

class DiskArtifact(TypedDict):
    artifact_type: str
    source_path: str
    timestamp: str
    details: DiskArtifactDetails

class MemoryProcess(TypedDict):
    pid: int
    ppid: int
    process_name: str
    path: str
    handles_count: int

class CorrelatedEvent(TypedDict):
    timestamp: str
    source_module: Literal["disk", "memory", "intake"]
    event_type: str
    description: str
    risk_score: int
    raw_data: dict  # Retained for backwards compatibility if needed internally
