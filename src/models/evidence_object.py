"""Pydantic schemas and Data Contracts for CyberTrace."""

from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime


class RiskBand(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingCategory(str, Enum):
    OBSERVED_EVIDENCE = "OBSERVED_EVIDENCE"
    INFRASTRUCTURE_ASSOCIATION = "INFRASTRUCTURE_ASSOCIATION"
    INFERENCE = "INFERENCE"


class ConfidenceLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERIFIED = "VERIFIED"


class RawEvidence(BaseModel):
    object_uri: str
    sha256: str
    size_bytes: int
    original_filename: str
    mime_type: str = "message/rfc822"


class CustodyEvent(BaseModel):
    event_id: str
    actor: str
    action: str
    timestamp: datetime
    evidence_hash: str


class Finding(BaseModel):
    id: str                                  # e.g., "F-001"
    module: str                              # e.g., "reconstruction", "header_forensics"
    category: FindingCategory
    claim: str
    evidence_refs: List[str] = Field(default_factory=list)  # e.g., ["H-002", "U-001"]
    confidence: ConfidenceLevel


class IndicatorSet(BaseModel):
    urls: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    qr_payloads: List[str] = Field(default_factory=list)
    attachments: List[Dict[str, Any]] = Field(default_factory=list)


class EmailContent(BaseModel):
    headers: Dict[str, Any] = Field(default_factory=dict)
    body_raw: str = ""
    body_normalized: str = ""
    hidden_content_removed: List[str] = Field(default_factory=list)
    multipart_mismatch: bool = False


class RiskAssessment(BaseModel):
    score: float = 0.0                       # Range [0.0, 1.0]
    band: RiskBand = RiskBand.LOW
    component_scores: Dict[str, float] = Field(default_factory=dict)
    component_weights: Dict[str, float] = Field(default_factory=dict)
    rationale: str = ""


class SimilarityMatch(BaseModel):
    case_id: str
    similarity_score: float
    drivers: List[str] = Field(default_factory=list)


class AttackDNA(BaseModel):
    vector: List[float] = Field(default_factory=list)
    top_matches: List[SimilarityMatch] = Field(default_factory=list)


class NarrativeStep(BaseModel):
    step_number: int
    statement: str
    cited_findings: List[str] = Field(default_factory=list)


class EvidenceObject(BaseModel):
    case_id: str
    ingested_at: datetime
    processing_status: str = "QUEUED"
    evidence: RawEvidence
    email: EmailContent = Field(default_factory=EmailContent)
    indicators: IndicatorSet = Field(default_factory=IndicatorSet)
    findings: List[Finding] = Field(default_factory=list)
    risk: RiskAssessment = Field(default_factory=RiskAssessment)
    attack_dna: AttackDNA = Field(default_factory=AttackDNA)
    attack_story: List[NarrativeStep] = Field(default_factory=list)
    chain_of_custody: List[CustodyEvent] = Field(default_factory=list)
