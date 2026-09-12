"""Tests for Module 3 (Header Forensics) & Module 4 (Authentication Validator)."""

import email
from email import policy
from src.modules.auth_validator import validate_authentication
from src.modules.header_forensics import analyze_headers
from src.modules.ingestion import ingest_raw_email


def test_header_forensics_flags_spoof_and_reply_to_mismatch(phishing_eml_bytes, temp_storage):
    evidence = ingest_raw_email(phishing_eml_bytes, "phishing.eml", storage_dir=temp_storage)
    msg = email.message_from_bytes(phishing_eml_bytes, policy=policy.default)
    
    evidence = analyze_headers(evidence, msg)
    
    finding_ids = [f.id for f in evidence.findings]
    # Reply-To mismatch
    assert "F-HDR-01" in finding_ids
    # Display name PayPal brand spoof
    assert "F-HDR-02" in finding_ids
    # Missing brackets or non-RFC Message-ID
    assert "F-HDR-03" in finding_ids
    
    # Assert Received hops parsed
    hops = evidence.email.headers.get("_parsed_received_hops", [])
    assert len(hops) >= 1
    assert hops[0]["ip"] == "203.0.113.88"


def test_auth_validator_detects_failures(phishing_eml_bytes, temp_storage):
    evidence = ingest_raw_email(phishing_eml_bytes, "phishing.eml", storage_dir=temp_storage)
    msg = email.message_from_bytes(phishing_eml_bytes, policy=policy.default)
    
    evidence = validate_authentication(evidence, msg)
    
    finding_ids = [f.id for f in evidence.findings]
    assert "F-AUTH-01" in finding_ids
    
    verdicts = evidence.email.headers.get("_auth_verdicts", {})
    assert verdicts["spf"] == "fail"
    assert verdicts["dkim"] == "fail"
    assert verdicts["dmarc"] == "fail"


def test_auth_validator_clean_email_passes(clean_eml_bytes, temp_storage):
    evidence = ingest_raw_email(clean_eml_bytes, "clean.eml", storage_dir=temp_storage)
    msg = email.message_from_bytes(clean_eml_bytes, policy=policy.default)
    
    evidence = validate_authentication(evidence, msg)
    
    verdicts = evidence.email.headers.get("_auth_verdicts", {})
    assert verdicts["spf"] == "pass"
    assert verdicts["dkim"] == "pass"
    assert verdicts["dmarc"] == "pass"
