"""Module 6: Explainable Mathematical Risk Engine."""

import re
from typing import Any, Dict, List
from src.models.evidence_object import (
    ConfidenceLevel,
    EvidenceObject,
    Finding,
    FindingCategory,
    RiskAssessment,
    RiskBand,
)

# 8 Fixed mathematical component weights summing to exactly 1.00
COMPONENT_WEIGHTS = {
    "nlp_phishing_keyword": 0.25,
    "header_anomaly": 0.15,
    "auth_failure": 0.10,
    "url_reputation": 0.15,
    "infra_risk": 0.10,
    "qr_quishing": 0.10,
    "campaign_similarity": 0.10,
    "attachment_risk": 0.05,
}

PHISHING_KEYWORDS = [
    r"urgent\b", r"immediate action", r"account suspended", r"verify your account",
    r"password expir", r"unauthorized access", r"security alert", r"login immediately",
    r"wire transfer", r"invoice overdue", r"payment declined", r"gift card",
    r"crypto", r"bitcoin", r"confidential", r"click here to unlock", r"tax refund",
    r"update your payment", r"suspended permanently"
]

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".iso", ".vbs", ".js", ".bat", ".cmd", ".ps1", ".hta", ".cpl",
    ".docm", ".xlsm", ".pptm", ".jar", ".zip"
}


def _score_nlp_phishing(text: str) -> float:
    """Calculates NLP phishing intent score in range [0.0, 1.0]."""
    if not text:
        return 0.0
    text_lower = text.lower()
    matches = 0
    for kw in PHISHING_KEYWORDS:
        if re.search(kw, text_lower):
            matches += 1
    # Normalized score: 3+ matches triggers maximum score
    return min(matches / 3.0, 1.0)


def _score_header_anomaly(findings: List[Finding]) -> float:
    """Evaluates header inconsistencies (Reply-To mismatch, brand spoofing)."""
    score = 0.0
    finding_ids = [f.id for f in findings]
    if "F-HDR-01" in finding_ids:  # Reply-To mismatch
        score = max(score, 1.0)
    if "F-HDR-02" in finding_ids:  # Display Name Brand Impersonation
        score = max(score, 0.8)
    if "F-HDR-03" in finding_ids:  # Malformed Message-ID
        score = max(score, 0.5)
    return score


def _score_auth_failure(headers: Dict[str, Any], findings: List[Finding]) -> float:
    """Evaluates SPF, DKIM, and DMARC failures."""
    verdicts = headers.get("_auth_verdicts", {})
    spf = verdicts.get("spf", "none").lower()
    dkim = verdicts.get("dkim", "none").lower()
    dmarc = verdicts.get("dmarc", "none").lower()
    
    score = 0.0
    if dmarc == "fail":
        score = max(score, 1.0)
    elif dmarc == "none":
        score = max(score, 0.3)
        
    if spf in ("fail", "softfail"):
        score = max(score, 0.7)
    elif spf == "none":
        score = max(score, 0.3)
        
    if dkim == "fail":
        score = max(score, 0.8)
        
    return score


def _score_url_reputation(urls: List[str], domains: List[str]) -> float:
    """Evaluates URL and domain indicators (IP literals, punycode, high link count)."""
    if not urls:
        return 0.0
    score = 0.1  # Baseline benign URL presence
    
    for u in urls:
        # IP-literal URL e.g. http://192.0.2.1/login
        if re.search(r"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}", u):
            return 1.0
            
    for d in domains:
        if d.startswith("xn--") or any(ord(c) > 127 for c in d):
            return 0.9
        # Check suspicious TLDs
        if d.endswith((".top", ".xyz", ".cc", ".buzz", ".work", ".tk", ".ml", ".ga")):
            score = max(score, 0.7)
            
    if len(urls) > 5:
        score = max(score, 0.4)
        
    return score


def _score_infra_risk(ips: List[str]) -> float:
    """Evaluates infrastructure and relay origin risk."""
    if not ips:
        return 0.1
    # Non-private public IPs originating email
    return 0.3 if len(ips) > 1 else 0.1


def _score_qr_quishing(qr_payloads: List[str]) -> float:
    """Scores multimodal QR quishing presence."""
    return 1.0 if len(qr_payloads) > 0 else 0.0


def _score_campaign_similarity(evidence: EvidenceObject) -> float:
    """Retrieves top cosine similarity match from Attack DNA."""
    if evidence.attack_dna and evidence.attack_dna.top_matches:
        return max(m.similarity_score for m in evidence.attack_dna.top_matches)
    return 0.0


def _score_attachment_risk(attachments: List[Dict[str, Any]]) -> float:
    """Evaluates risk of file attachments."""
    if not attachments:
        return 0.0
    for att in attachments:
        fname = att.get("filename", "").lower()
        if any(fname.endswith(ext) for ext in RISKY_EXTENSIONS):
            return 1.0
    return 0.2


def calculate_risk(evidence: EvidenceObject) -> EvidenceObject:
    """Applies the 8-component explainable linear formula and assigns RiskBand."""
    # 1. Compute individual component scores [0.0, 1.0]
    nlp_score = _score_nlp_phishing(evidence.email.body_normalized or evidence.email.body_raw)
    hdr_score = _score_header_anomaly(evidence.findings)
    auth_score = _score_auth_failure(evidence.email.headers, evidence.findings)
    url_score = _score_url_reputation(evidence.indicators.urls, evidence.indicators.domains)
    infra_score = _score_infra_risk(evidence.indicators.ips)
    qr_score = _score_qr_quishing(evidence.indicators.qr_payloads)
    camp_score = _score_campaign_similarity(evidence)
    att_score = _score_attachment_risk(evidence.indicators.attachments)
    
    component_scores = {
        "nlp_phishing_keyword": round(nlp_score, 4),
        "header_anomaly": round(hdr_score, 4),
        "auth_failure": round(auth_score, 4),
        "url_reputation": round(url_score, 4),
        "infra_risk": round(infra_score, 4),
        "qr_quishing": round(qr_score, 4),
        "campaign_similarity": round(camp_score, 4),
        "attachment_risk": round(att_score, 4),
    }
    
    # 2. Linear weighted sum
    composite_score = sum(component_scores[k] * COMPONENT_WEIGHTS[k] for k in COMPONENT_WEIGHTS)
    composite_score = round(min(max(composite_score, 0.0), 1.0), 4)
    
    # 3. Determine Risk Band
    if composite_score >= 0.85:
        band = RiskBand.CRITICAL
    elif composite_score >= 0.65:
        band = RiskBand.HIGH
    elif composite_score >= 0.35:
        band = RiskBand.MEDIUM
    else:
        band = RiskBand.LOW
        
    # 4. Generate explainable mathematical rationale
    top_drivers = sorted(
        [(k, component_scores[k] * COMPONENT_WEIGHTS[k]) for k in component_scores],
        key=lambda x: x[1],
        reverse=True
    )
    primary_driver = top_drivers[0][0]
    secondary_driver = top_drivers[1][0]
    
    rationale = (
        f"Composite Risk Score: {composite_score:.2f} ({band.value}). "
        f"Primary risk driver is '{primary_driver}' (weighted contribution: {top_drivers[0][1]:.3f}) "
        f"followed by '{secondary_driver}' (contribution: {top_drivers[1][1]:.3f})."
    )
    
    evidence.risk = RiskAssessment(
        score=composite_score,
        band=band,
        component_scores=component_scores,
        component_weights=COMPONENT_WEIGHTS,
        rationale=rationale,
    )
    
    return evidence
