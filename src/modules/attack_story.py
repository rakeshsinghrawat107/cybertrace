"""Module 8: Programmatic Citation-Constrained Incident Narrative (Zero-Hallucination Storytelling)."""

import re
from typing import List, Set
from src.models.evidence_object import (
    EvidenceObject,
    Finding,
    NarrativeStep,
)

CITATION_REGEX = re.compile(r"\[(F-[A-Z0-9\-]+)\]")


def generate_grounded_story(evidence: EvidenceObject) -> EvidenceObject:
    """Generates a chronological forensic narrative where every statement MUST cite verified findings.
    
    Any sentence lacking an explicit, verifiable finding reference token [F-XXX] is discarded.
    """
    valid_finding_ids: Set[str] = {f.id for f in evidence.findings}
    findings_map = {f.id: f for f in evidence.findings}
    
    candidate_steps: List[str] = []
    
    # 1. Ingestion & Preservation step
    candidate_steps.append(
        f"Cryptographic Evidence Ingestion: The unparsed message stream was received and immutably sealed under SHA-256 digest {evidence.evidence.sha256[:16]}..."
        # Notice: This ungrounded sentence has no [F-XXX] and will be safely evaluated by validator
    )
    
    # 2. Authentication findings
    if "F-AUTH-01" in valid_finding_ids:
        candidate_steps.append(
            f"Perimeter Authentication Check: Domain authorization protocols were evaluated with recorded verdict [F-AUTH-01]."
        )
        
    # 3. Header forensics & spoofing findings
    if "F-HDR-02" in valid_finding_ids:
        candidate_steps.append(
            f"Sender Identity Deception: The message displays brand impersonation hooks designed to mislead recipients [F-HDR-02]."
        )
    if "F-HDR-01" in valid_finding_ids:
        candidate_steps.append(
            f"Exfiltration & Response Redirection: Adversary configured an out-of-band response channel via mismatched Reply-To routing [F-HDR-01]."
        )
    if "F-HDR-03" in valid_finding_ids:
        candidate_steps.append(
            f"Envelope Anomaly: The transmission envelope lacks compliant RFC Message-ID tokens [F-HDR-03]."
        )
        
    # 4. Obfuscation & Cloaking findings
    if "F-OBFUSCATION" in valid_finding_ids:
        candidate_steps.append(
            f"Adversarial Evasion: Payload incorporates zero-width non-printable Unicode characters to defeat NLP tokenizers [F-OBFUSCATION]."
        )
    if "F-HIDDEN-DOM" in valid_finding_ids:
        candidate_steps.append(
            f"CSS Cloaking Extraction: Adversary embedded invisible DOM elements to camouflage malicious text from security gateways [F-HIDDEN-DOM]."
        )
    if "F-MIME" in valid_finding_ids:
        candidate_steps.append(
            f"MIME Desynchronization: Divergence observed between plain text and HTML components [F-MIME]."
        )
        
    # 5. QR Quishing findings
    if "F-QR-01" in valid_finding_ids:
        candidate_steps.append(
            f"Multimodal Delivery: In-memory computer vision successfully recovered a high-risk QR quishing destination payload [F-QR-01]."
        )
        
    # Candidate narrative validator
    validated_steps: List[NarrativeStep] = []
    step_counter = 1
    
    for sentence in candidate_steps:
        # Check citations
        found_citations = CITATION_REGEX.findall(sentence)
        verified_citations = [c for c in found_citations if c in valid_finding_ids]
        
        # Invariant: Must have at least one valid finding token
        if verified_citations:
            validated_steps.append(
                NarrativeStep(
                    step_number=step_counter,
                    statement=sentence,
                    cited_findings=verified_citations,
                )
            )
            step_counter += 1
            
    evidence.attack_story = validated_steps
    return evidence
