"""Tests for Module 1: Safe Intake & Preservation Before Parsing."""

import hashlib
from pathlib import Path
from src.modules.ingestion import ingest_raw_email


def test_ingestion_preserves_raw_bytes_and_hash(clean_eml_bytes, temp_storage):
    filename = "clean_sample.eml"
    expected_sha256 = hashlib.sha256(clean_eml_bytes).hexdigest()
    
    evidence = ingest_raw_email(clean_eml_bytes, filename, storage_dir=temp_storage)
    
    assert evidence.case_id.startswith("CT-2026-")
    assert evidence.evidence.sha256 == expected_sha256
    assert evidence.evidence.size_bytes == len(clean_eml_bytes)
    assert evidence.evidence.original_filename == filename
    
    # Assert physical file written matches original bytes bit-for-bit
    saved_file = Path(evidence.evidence.object_uri)
    assert saved_file.exists()
    assert saved_file.read_bytes() == clean_eml_bytes
    
    # Assert initial custody event
    assert len(evidence.chain_of_custody) == 1
    custody_0 = evidence.chain_of_custody[0]
    assert custody_0.event_id == "EV-001"
    assert custody_0.action == "RAW_INTAKE"
    assert custody_0.evidence_hash == expected_sha256
