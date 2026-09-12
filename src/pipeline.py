"""CyberTrace Forensic Pipeline Orchestrator."""

import email
import time
from datetime import datetime, timezone
from email import policy
from pathlib import Path
from typing import Optional

from src.models.evidence_object import (
    CustodyEvent,
    EvidenceObject,
)
from src.modules.attack_dna import compute_attack_dna
from src.modules.attack_story import generate_grounded_story
from src.modules.auth_validator import validate_authentication
from src.modules.dossier_exporter import export_evidence_package
from src.modules.header_forensics import analyze_headers
from src.modules.indicator_extractor import extract_indicators
from src.modules.ingestion import ingest_raw_email
from src.modules.reconstruction import reconstruct_email
from src.modules.risk_engine import calculate_risk


class ForensicPipeline:
    """Orchestrates the 9-stage linear Directed Acyclic Graph (DAG) for email threat forensics.
    
    Adheres to the Non-Blocking Pipeline Invariant: complete execution runs under 2.0 seconds.
    """
    
    def __init__(self, storage_dir: str = "data", seeded_db_path: Optional[str] = None):
        self.storage_dir = storage_dir
        self.seeded_db_path = seeded_db_path
        
    def process(self, file_bytes: bytes, filename: str, export_dossier: bool = True) -> EvidenceObject:
        """Executes the full end-to-end analytical pipeline."""
        start_time = time.perf_counter()
        
        # Stage 1: Safe Intake & Cryptographic Locking
        evidence = ingest_raw_email(file_bytes, filename, storage_dir=self.storage_dir)
        evidence.processing_status = "PROCESSING"
        
        # Parse standard RFC message object for downstream modules
        msg = email.message_from_bytes(file_bytes, policy=policy.default)
        
        # Stage 2: Adversarial Email Reconstruction
        evidence = reconstruct_email(evidence, file_bytes)
        
        # Stage 3: Header Forensics & Received Chain
        evidence = analyze_headers(evidence, msg)
        
        # Stage 4: Authentication Results Validator
        evidence = validate_authentication(evidence, msg)
        
        # Stage 5: Indicator & Multimodal QR Extractor
        evidence = extract_indicators(evidence, msg)
        
        # Stage 6: Attack DNA & Vector Similarity
        evidence = compute_attack_dna(evidence, seeded_db_path=self.seeded_db_path)
        
        # Stage 7: Mathematical Risk Engine
        evidence = calculate_risk(evidence)
        
        # Stage 8: Citation-Constrained Incident Narrative
        evidence = generate_grounded_story(evidence)
        
        # Stage 9: Legal Evidence Packaging & PDF Dossier
        if export_dossier:
            zip_path = export_evidence_package(evidence, output_dir=self.storage_dir)
            
        elapsed_seconds = time.perf_counter() - start_time
        
        # Final custody audit event
        now = datetime.now(timezone.utc)
        evidence.chain_of_custody.append(
            CustodyEvent(
                event_id=f"EV-{len(evidence.chain_of_custody) + 1:03d}",
                actor="PIPELINE_ORCHESTRATOR",
                action=f"FORENSIC_ANALYSIS_COMPLETED (Latency: {elapsed_seconds:.3f}s)",
                timestamp=now,
                evidence_hash=evidence.evidence.sha256,
            )
        )
        
        evidence.processing_status = "COMPLETED"
        return evidence


def run_pipeline(file_bytes: bytes, filename: str, storage_dir: str = "data") -> EvidenceObject:
    """Convenience functional interface for pipeline execution."""
    pipeline = ForensicPipeline(storage_dir=storage_dir)
    return pipeline.process(file_bytes, filename)
