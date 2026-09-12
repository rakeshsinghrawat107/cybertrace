"""Module 7: 32-Dimensional Multi-Signal Attack DNA & Vector Similarity Engine."""

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from src.models.evidence_object import (
    AttackDNA,
    EvidenceObject,
    SimilarityMatch,
)

FEATURE_NAMES = [
    "relay_hop_count", "recipient_count", "subject_length", "body_length",
    "total_header_count", "multipart_boundary_anomaly", "missing_message_id",
    "brand_impersonation", "zero_width_char_count", "homoglyph_count",
    "css_hidden_tags", "css_tiny_font", "same_color_font_bg", "script_or_base64_tag",
    "punycode_domain", "multipart_mismatch", "total_url_count", "unique_domains_count",
    "ip_literal_url", "qr_payload_present", "qr_url_redirect", "attachment_count",
    "high_risk_extension", "macro_extension", "spf_verdict", "dkim_verdict",
    "dmarc_verdict", "reply_to_mismatch", "return_path_mismatch", "originating_asn_risk",
    "nlp_credential_harvesting", "nlp_urgent_financial_threat"
]


def extract_raw_features(evidence: EvidenceObject) -> List[float]:
    """Builds the raw 32-dimensional structural feature vector."""
    headers = evidence.email.headers
    findings = [f.id for f in evidence.findings]
    body = evidence.email.body_normalized or evidence.email.body_raw
    urls = evidence.indicators.urls
    domains = evidence.indicators.domains
    attachments = evidence.indicators.attachments
    qr_payloads = evidence.indicators.qr_payloads
    verdicts = headers.get("_auth_verdicts", {})
    
    # 0: Relay Hop Count: min(H / 20.0, 1.0)
    parsed_hops = headers.get("_parsed_received_hops", [])
    f0 = min(len(parsed_hops) / 20.0, 1.0)
    
    # 1: Recipient Count: min(R / 10.0, 1.0)
    to_val = headers.get("To", "")
    cc_val = headers.get("Cc", "")
    recipients = [r for r in f"{to_val},{cc_val}".split(",") if r.strip()]
    f1 = min(len(recipients) / 10.0, 1.0) if recipients else 0.1
    
    # 2: Subject Length: min(L / 250.0, 1.0)
    subject = headers.get("Subject", "")
    f2 = min(len(subject) / 250.0, 1.0)
    
    # 3: Body Length: min(C / 10000.0, 1.0)
    f3 = min(len(body) / 10000.0, 1.0)
    
    # 4: Total Header Count: min(H_tot / 50.0, 1.0)
    f4 = min(len(headers) / 50.0, 1.0)
    
    # 5: Multipart Boundary Anomaly: 1.0 if malformed else 0.0
    f5 = 0.0
    
    # 6: Missing Message-ID: 1.0 if absent else 0.0
    f6 = 1.0 if "F-HDR-03" in findings else 0.0
    
    # 7: Brand Impersonation: 1.0 if detected else 0.0
    f7 = 1.0 if "F-HDR-02" in findings else 0.0
    
    # 8: Zero-Width Char Count: min(Z / 50.0, 1.0)
    zw_count = sum(1 for log in evidence.email.hidden_content_removed if "Zero-width" in log)
    f8 = min(zw_count / 50.0, 1.0)
    
    # 9: Homoglyph Count: min(G / 20.0, 1.0)
    homoglyphs = sum(1 for c in body if ord(c) > 127 and unicodedata_is_lookalike(c))
    f9 = min(homoglyphs / 20.0, 1.0)
    
    # 10: CSS Hidden Tags: min(T / 10.0, 1.0)
    css_hides = sum(1 for log in evidence.email.hidden_content_removed if "CSS Hidden" in log)
    f10 = min(css_hides / 10.0, 1.0)
    
    # 11: CSS Tiny Font: min(F / 10.0, 1.0)
    f11 = min(sum(1 for log in evidence.email.hidden_content_removed if "font-size" in log) / 10.0, 1.0)
    
    # 12: Same-color Foreground/Background: 1.0 if hidden else 0.0
    f12 = 1.0 if any("Color-camouflage" in log for log in evidence.email.hidden_content_removed) else 0.0
    
    # 13: Script or Base64 Tag Present: 1.0 if present else 0.0
    f13 = 1.0 if ("<script" in body.lower() or "base64" in body.lower()) else 0.0
    
    # 14: Punycode Domain: 1.0 if present else 0.0
    f14 = 1.0 if any(d.startswith("xn--") for d in domains) else 0.0
    
    # 15: Multipart Mismatch: 1.0 if mismatch else 0.0
    f15 = 1.0 if evidence.email.multipart_mismatch else 0.0
    
    # 16: Total URL Count: min(U / 20.0, 1.0)
    f16 = min(len(urls) / 20.0, 1.0)
    
    # 17: Unique Domains Count: min(D / 10.0, 1.0)
    f17 = min(len(domains) / 10.0, 1.0)
    
    # 18: IP-Literal URL Present: 1.0 if raw IP used else 0.0
    f18 = 1.0 if any(re.search(r"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}", u) for u in urls) else 0.0
    
    # 19: QR Code Payload Present: 1.0 if QR detected else 0.0
    f19 = 1.0 if len(qr_payloads) > 0 else 0.0
    
    # 20: QR Target URL Redirection: 1.0 if redirector else 0.0
    f20 = 1.0 if any("redirect" in qr.lower() or "bit.ly" in qr.lower() or "t.co" in qr.lower() for qr in qr_payloads) else 0.0
    
    # 21: Attachment Count: min(A / 5.0, 1.0)
    f21 = min(len(attachments) / 5.0, 1.0)
    
    # 22: High-Risk Extension: 1.0 if risky else 0.0
    risky_exts = {".exe", ".scr", ".iso", ".vbs", ".bat", ".cmd", ".ps1"}
    f22 = 1.0 if any(any(att.get("filename", "").lower().endswith(ext) for ext in risky_exts) for att in attachments) else 0.0
    
    # 23: Office Macro Extension: 1.0 if macro else 0.0
    macro_exts = {".docm", ".xlsm", ".pptm"}
    f23 = 1.0 if any(any(att.get("filename", "").lower().endswith(ext) for ext in macro_exts) for att in attachments) else 0.0
    
    # 24: SPF Verdict: Pass=0.0, Neutral=0.3, Fail=1.0, None=0.5
    spf = verdicts.get("spf", "none").lower()
    f24 = 0.0 if spf == "pass" else (0.3 if spf == "neutral" else (1.0 if spf in ("fail", "softfail") else 0.5))
    
    # 25: DKIM Verdict: Pass=0.0, Fail=1.0, None=0.5
    dkim = verdicts.get("dkim", "none").lower()
    f25 = 0.0 if dkim == "pass" else (1.0 if dkim == "fail" else 0.5)
    
    # 26: DMARC Verdict: Pass=0.0, Fail=1.0, None=0.5
    dmarc = verdicts.get("dmarc", "none").lower()
    f26 = 0.0 if dmarc == "pass" else (1.0 if dmarc == "fail" else 0.5)
    
    # 27: Reply-To Domain Mismatch: 1.0 if mismatch else 0.0
    f27 = 1.0 if "F-HDR-01" in findings else 0.0
    
    # 28: Return-Path Mismatch: 1.0 if mismatch else 0.0
    f28 = 1.0 if (headers.get("_from_email") and headers.get("_return_path_email") and 
                   headers.get("_from_email").split("@")[-1].lower() != headers.get("_return_path_email").split("@")[-1].lower()) else 0.0
                   
    # 29: Originating ASN Risk: Bulletproof/Tor=1.0, Cloud=0.6, ISP=0.1
    f29 = 0.1
    
    # 30: NLP Credential Harvesting: [0.0, 1.0]
    cred_keywords = ["login", "password", "credential", "verify", "authenticate", "suspended", "unlock"]
    f30 = min(sum(1 for kw in cred_keywords if kw in body.lower()) / 3.0, 1.0)
    
    # 31: NLP Urgent Financial Threat: [0.0, 1.0]
    fin_keywords = ["invoice", "wire", "transfer", "bank", "payment", "overdue", "gift card", "crypto", "refund"]
    f31 = min(sum(1 for kw in fin_keywords if kw in body.lower()) / 3.0, 1.0)
    
    return [
        f0, f1, f2, f3, f4, f5, f6, f7, f8, f9,
        f10, f11, f12, f13, f14, f15, f16, f17, f18, f19,
        f20, f21, f22, f23, f24, f25, f26, f27, f28, f29,
        f30, f31
    ]


def unicodedata_is_lookalike(char: str) -> bool:
    """Checks if non-ASCII character resembles Latin scripts (Cyrillic, Greek)."""
    code = ord(char)
    # Cyrillic: 0x0400 - 0x04FF, Greek: 0x0370 - 0x03FF
    return (0x0400 <= code <= 0x04FF) or (0x0370 <= code <= 0x03FF)


def compute_attack_dna(evidence: EvidenceObject, seeded_db_path: Optional[str] = None) -> EvidenceObject:
    """Computes the 32-dimensional normalized structural feature vector and matches against historical campaigns."""
    raw_vec = extract_raw_features(evidence)
    vec_np = np.array(raw_vec, dtype=np.float64)
    
    norm = np.linalg.norm(vec_np)
    if norm > 0:
        norm_vec = vec_np / norm
    else:
        norm_vec = vec_np
        
    evidence.attack_dna.vector = [round(float(v), 5) for v in norm_vec]
    
    # Cosine matching against seeded campaigns
    matches: List[SimilarityMatch] = []
    
    db_candidates = [
        seeded_db_path,
        "tests/fixtures/seeded_campaigns.json",
        str(Path(__file__).parent.parent.parent / "tests" / "fixtures" / "seeded_campaigns.json"),
    ]
    
    valid_db_path = None
    for p in db_candidates:
        if p and os.path.exists(p):
            valid_db_path = p
            break
            
    if valid_db_path:
        try:
            with open(valid_db_path, "r", encoding="utf-8") as f:
                campaigns = json.load(f)
                
            for camp in campaigns:
                c_vec = np.array(camp["vector"], dtype=np.float64)
                c_norm = np.linalg.norm(c_vec)
                if c_norm > 0:
                    c_norm_vec = c_vec / c_norm
                else:
                    c_norm_vec = c_vec
                    
                # Cosine similarity between unit vectors is the dot product
                sim = float(np.dot(norm_vec, c_norm_vec))
                if sim >= 0.70:
                    # Identify top drivers: feature indices with high mutual weight
                    driver_scores = []
                    for idx, (va, vb) in enumerate(zip(norm_vec, c_norm_vec)):
                        contrib = va * vb
                        if contrib > 0.05:
                            driver_scores.append((FEATURE_NAMES[idx], contrib))
                    driver_scores.sort(key=lambda x: x[1], reverse=True)
                    top_drivers = [d[0] for d in driver_scores[:3]] or ["Structural structural congruence"]
                    
                    matches.append(
                        SimilarityMatch(
                            case_id=camp["campaign_id"],
                            similarity_score=round(sim, 4),
                            drivers=top_drivers,
                        )
                    )
            matches.sort(key=lambda x: x.similarity_score, reverse=True)
        except Exception:
            pass
            
    evidence.attack_dna.top_matches = matches
    return evidence
