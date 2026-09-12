"""CyberTrace Production FastAPI REST Service."""

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from src.models.evidence_object import EvidenceObject
from src.pipeline import ForensicPipeline

app = FastAPI(
    title="CyberTrace Forensic Intelligence API",
    description="AI-Powered Email Threat Detection, Protocol Forensics & Section 63 BSA Digital Evidence Packaging",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global in-memory cache for ultra-low latency case retrieval
CASES_REGISTRY: Dict[str, EvidenceObject] = {}
STORAGE_DIR = "data"
pipeline = ForensicPipeline(storage_dir=STORAGE_DIR)


def _load_case_from_disk(case_id: str) -> Optional[EvidenceObject]:
    """Loads EvidenceObject from disk storage if not in memory."""
    if case_id in CASES_REGISTRY:
        return CASES_REGISTRY[case_id]
        
    json_path = Path(STORAGE_DIR) / case_id / "evidence_object.json"
    if json_path.exists():
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            obj = EvidenceObject(**data)
            CASES_REGISTRY[case_id] = obj
            return obj
        except Exception:
            return None
    return None


@app.get("/health", tags=["Health"])
async def health_check() -> Dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "CyberTrace", "version": "1.0.0"}


@app.post("/cases", response_model=EvidenceObject, status_code=status.HTTP_201_CREATED, tags=["Forensics"])
async def ingest_case(file: UploadFile = File(...)) -> EvidenceObject:
    """Ingests raw `.eml` bytes, seals under SHA-256 digest, executes all 9 forensic modules, and returns complete EvidenceObject."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing file name.")
        
    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
        
    evidence = pipeline.process(file_bytes, filename=file.filename, export_dossier=True)
    CASES_REGISTRY[evidence.case_id] = evidence
    return evidence


@app.get("/cases/{case_id}", response_model=EvidenceObject, tags=["Forensics"])
async def get_case(case_id: str) -> EvidenceObject:
    """Retrieves full EvidenceObject forensic report for a given case ID."""
    evidence = _load_case_from_disk(case_id)
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Case ID '{case_id}' not found.")
    return evidence


@app.post("/cases/{case_id}/verify", tags=["Forensics"])
async def verify_case_integrity(case_id: str, file: UploadFile = File(...)) -> Dict[str, Any]:
    """Mathematical verification endpoint proving Zero Hash Drift under Section 63 BSA 2023.
    
    Re-hashes the re-uploaded `.eml` and verifies bit-for-bit equality against the original intake digest.
    """
    evidence = _load_case_from_disk(case_id)
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Case ID '{case_id}' not found.")
        
    reupload_bytes = await file.read()
    reupload_hash = hashlib.sha256(reupload_bytes).hexdigest()
    original_hash = evidence.evidence.sha256
    is_match = (reupload_hash == original_hash)
    
    return {
        "case_id": case_id,
        "verified": True,
        "match": is_match,
        "original_hash": original_hash,
        "uploaded_hash": reupload_hash,
        "status": "CRYPTOGRAPHIC_MATCH" if is_match else "HASH_DRIFT_DETECTED",
        "legal_admissibility": "VALID_SECTION_63_BSA" if is_match else "INVALID_TAMPERED",
    }


@app.get("/cases/{case_id}/report.pdf", tags=["Dossier"])
async def download_forensic_report_pdf(case_id: str) -> FileResponse:
    """Streams court-admissible Section 63 BSA audit PDF report."""
    evidence = _load_case_from_disk(case_id)
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Case ID '{case_id}' not found.")
        
    pdf_path = Path(STORAGE_DIR) / case_id / "CyberTrace_Forensic_Report.pdf"
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="Forensic PDF report not found.")
        
    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"CyberTrace_{case_id}_Report.pdf",
    )


@app.get("/cases/{case_id}/evidence.zip", tags=["Dossier"])
async def download_evidence_zip_bundle(case_id: str) -> FileResponse:
    """Streams complete tamper-evident Section 63 BSA ZIP bundle (EML, checksums, PDF, JSON, IoCs)."""
    evidence = _load_case_from_disk(case_id)
    if not evidence:
        raise HTTPException(status_code=404, detail=f"Case ID '{case_id}' not found.")
        
    zip_path = Path(STORAGE_DIR) / case_id / f"CT-{case_id}_evidence_package.zip"
    if not zip_path.exists():
        raise HTTPException(status_code=404, detail="Forensic evidence ZIP bundle not found.")
        
    return FileResponse(
        path=str(zip_path),
        media_type="application/zip",
        filename=f"CT-{case_id}_evidence_package.zip",
    )
