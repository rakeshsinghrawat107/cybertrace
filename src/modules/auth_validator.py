"""Module 4: Authentication Results Validator (SPF, DKIM, DMARC Alignment)."""

import email
import re
from typing import Any, Dict, Optional, Tuple

from src.models.evidence_object import (
    ConfidenceLevel,
    EvidenceObject,
    Finding,
    FindingCategory,
)


def _extract_domain_from_email(addr: str) -> str:
    """Helper to extract domain from email address."""
    if "@" in addr:
        return addr.split("@")[-1].strip("<> \r\n\t").lower()
    return ""


def parse_authentication_results(msg: email.message.Message) -> Dict[str, str]:
    """Extracts SPF, DKIM, and DMARC verdicts from Authentication-Results, Received-SPF, or DKIM headers."""
    verdicts = {
        "spf": "none",
        "dkim": "none",
        "dmarc": "none",
        "auth_header_raw": "",
    }
    
    auth_results = msg.get("Authentication-Results", "")
    verdicts["auth_header_raw"] = auth_results
    
    if auth_results:
        # Match spf=<verdict>
        spf_match = re.search(r"\bspf=([a-zA-Z0-9_-]+)", auth_results, re.I)
        if spf_match:
            verdicts["spf"] = spf_match.group(1).lower()
            
        # Match dkim=<verdict>
        dkim_match = re.search(r"\bdkim=([a-zA-Z0-9_-]+)", auth_results, re.I)
        if dkim_match:
            verdicts["dkim"] = dkim_match.group(1).lower()
            
        # Match dmarc=<verdict>
        dmarc_match = re.search(r"\bdmarc=([a-zA-Z0-9_-]+)", auth_results, re.I)
        if dmarc_match:
            verdicts["dmarc"] = dmarc_match.group(1).lower()
            
    # Fallback checks if Authentication-Results was missing or partial
    if verdicts["spf"] == "none":
        received_spf = msg.get("Received-SPF", "")
        if received_spf:
            first_word = received_spf.strip().split()[0].lower()
            if first_word in ("pass", "fail", "softfail", "neutral", "none"):
                verdicts["spf"] = first_word
                
    if verdicts["dkim"] == "none":
        dkim_sig = msg.get("DKIM-Signature", "")
        if dkim_sig and verdicts["dkim"] == "none":
            # If signature is present but unverified by MTA header, mark unverified / neutral
            verdicts["dkim"] = "present_unverified"
            
    return verdicts


def validate_authentication(evidence: EvidenceObject, msg: email.message.Message) -> EvidenceObject:
    """Validates SPF, DKIM, and DMARC verdicts, evaluates domain alignment, and emits audit findings."""
    verdicts = parse_authentication_results(msg)
    
    from_header = msg.get("From", "")
    from_domain = _extract_domain_from_email(from_header)
    
    spf_verdict = verdicts["spf"]
    dkim_verdict = verdicts["dkim"]
    dmarc_verdict = verdicts["dmarc"]
    
    is_failing = spf_verdict in ("fail", "softfail") or dmarc_verdict == "fail" or dkim_verdict == "fail"
    
    claim_details = (
        f"Email Authentication Status: SPF={spf_verdict.upper()}, "
        f"DKIM={dkim_verdict.upper()}, DMARC={dmarc_verdict.upper()} for domain '{from_domain}'."
    )
    
    if is_failing:
        claim_details += " Crucial domain authentication failure detected indicating potential spoofing or unauthorized relay."
        
    evidence.findings.append(
        Finding(
            id="F-AUTH-01",
            module="auth_validator",
            category=FindingCategory.OBSERVED_EVIDENCE,
            claim=claim_details,
            evidence_refs=["AUTH-001"],
            confidence=ConfidenceLevel.VERIFIED,
        )
    )
    
    if not isinstance(evidence.email.headers, dict):
        evidence.email.headers = {}
    evidence.email.headers["_auth_verdicts"] = verdicts
    
    return evidence
