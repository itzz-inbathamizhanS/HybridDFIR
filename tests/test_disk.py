import pytest
import os
import json
from pathlib import Path
from src.disk.fs_parser import FileSystemParser
from src.disk.artifact_extractor import ArtifactExtractor

@pytest.fixture
def mock_filesystem(tmp_path):
    """Creates a mock Windows file system structure for testing."""
    # Create SYSTEM registry hive path
    sys_hive_dir = tmp_path / "Windows" / "System32" / "config"
    sys_hive_dir.mkdir(parents=True)
    sys_hive = sys_hive_dir / "SYSTEM"
    sys_hive.write_text("dummy registry data")
    
    # Create Prefetch directory and file
    prefetch_dir = tmp_path / "Windows" / "Prefetch"
    prefetch_dir.mkdir(parents=True)
    pf_file = prefetch_dir / "CMD-12345678.pf"
    pf_file.write_text("dummy prefetch data")
    
    # Create a random file to ensure search logic isolates correctly
    random_dir = tmp_path / "Users" / "Test"
    random_dir.mkdir(parents=True)
    (random_dir / "SYSTEM").write_text("not the real system hive")
    
    return tmp_path

def test_fs_parser_locate_file(mock_filesystem):
    parser = FileSystemParser(str(mock_filesystem))
    matches = parser.locate_file("SYSTEM")
    
    assert len(matches) == 2
    assert any("config" in p and "System32" in p for p in matches)
    assert any("Users" in p and "Test" in p for p in matches)

def test_fs_parser_get_file_metadata(mock_filesystem):
    parser = FileSystemParser(str(mock_filesystem))
    sys_hive = mock_filesystem / "Windows" / "System32" / "config" / "SYSTEM"
    
    meta = parser.get_file_metadata(str(sys_hive))
    assert "created_utc" in meta
    assert "modified_utc" in meta
    assert "accessed_utc" in meta
    assert "size_bytes" in meta
    assert meta["size_bytes"] > 0

def test_fs_parser_invalid_mount():
    with pytest.raises(FileNotFoundError):
        FileSystemParser("/non/existent/path")

def test_extractor_system_registry(mock_filesystem):
    extractor = ArtifactExtractor(str(mock_filesystem))
    artifacts = extractor.extract_system_registry()
    
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact["artifact_type"] == "Registry Hive"
    assert "config" in artifact["source_path"].lower()
    assert artifact["details"]["hive_type"] == "SYSTEM"

def test_extractor_prefetch(mock_filesystem):
    extractor = ArtifactExtractor(str(mock_filesystem))
    artifacts = extractor.extract_prefetch()
    
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact["artifact_type"] == "Prefetch File"
    assert "CMD" in artifact["source_path"]
    assert artifact["details"]["executable_identified"] == "CMD.exe"

def test_extractor_all_artifacts(mock_filesystem):
    extractor = ArtifactExtractor(str(mock_filesystem))
    artifacts = extractor.extract_all_artifacts()
    
    assert len(artifacts) == 2
    types = [a["artifact_type"] for a in artifacts]
    assert "Registry Hive" in types
    assert "Prefetch File" in types
