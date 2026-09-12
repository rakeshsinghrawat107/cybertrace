"""Tests for Module 5: Indicator Extraction & Multimodal QR Quishing Computer Vision."""

import email
from email import policy
from src.modules.indicator_extractor import extract_indicators
from src.modules.ingestion import ingest_raw_email


def test_qr_extractor_decodes_quishing_payload(quishing_eml_bytes, temp_storage):
    evidence = ingest_raw_email(quishing_eml_bytes, "quishing.eml", storage_dir=temp_storage)
    msg = email.message_from_bytes(quishing_eml_bytes, policy=policy.default)
    
    evidence = extract_indicators(evidence, msg)
    
    # Assert QR payload was extracted
    assert len(evidence.indicators.qr_payloads) >= 1
    assert "https://fake-login.paypal-secure.cc/verify" in evidence.indicators.qr_payloads
    
    # Assert finding was emitted
    finding_ids = [f.id for f in evidence.findings]
    assert "F-QR-01" in finding_ids
    
    # Assert destination domain added to indicators
    assert "fake-login.paypal-secure.cc" in evidence.indicators.domains


def test_indicator_extractor_handles_clean_email(clean_eml_bytes, temp_storage):
    evidence = ingest_raw_email(clean_eml_bytes, "clean.eml", storage_dir=temp_storage)
    msg = email.message_from_bytes(clean_eml_bytes, policy=policy.default)
    
    evidence = extract_indicators(evidence, msg)
    
    assert len(evidence.indicators.qr_payloads) == 0
    assert "https://portal.acme-corp.com/status" in evidence.indicators.urls
    assert "portal.acme-corp.com" in evidence.indicators.domains
