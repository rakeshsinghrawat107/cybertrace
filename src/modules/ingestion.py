"""Module 1: Safe Intake & Hashing (Preservation Before Parsing)."""

import hashlib
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from src.models.evidence_object import (
    CustodyEvent,
    EvidenceObject,
    RawEvidence,
)


def ingest_raw_email(file_bytes: bytes, filename: str, storage_dir: str = "data") -> EvidenceObject:
    """Ingests raw email bytes, locks cryptographic SHA-256 digest, writes raw file, and initializes custody.
    
    In accordance with the Preservation Invariant, no parsing or mutation occurs prior to digest locking.
    """
    case_id = f"CT-2026-{uuid.uuid4().hex[:5].upper()}"
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    
    case_dir = Path(storage_dir) / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    
    raw_path = case_dir / "raw.eml"
    with open(raw_path, "wb") as f:
        f.write(file_bytes)
        
    now = datetime.now(timezone.utc)
    
    raw_evidence = RawEvidence(
        object_uri=str(raw_path.resolve()),
        sha256=sha256_hash,
        size_bytes=len(file_bytes),
        original_filename=filename,
        mime_type="message/rfc822",
    )
    
    initial_custody = CustodyEvent(
        event_id="EV-001",
        actor="SYSTEM",
        action="RAW_INTAKE",
        timestamp=now,
        evidence_hash=sha256_hash,
    )
    
    return EvidenceObject(
        case_id=case_id,
        ingested_at=now,
        processing_status="QUEUED",
        evidence=raw_evidence,
        chain_of_custody=[initial_custody],
    )
