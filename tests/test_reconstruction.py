"""Tests for Module 2: Adversarial Reconstruction & De-Obfuscation."""

from src.modules.ingestion import ingest_raw_email
from src.modules.reconstruction import reconstruct_email


def test_reconstruction_detects_zero_width_and_hidden_dom(phishing_eml_bytes, temp_storage):
    evidence = ingest_raw_email(phishing_eml_bytes, "phishing_obfuscated.eml", storage_dir=temp_storage)
    evidence = reconstruct_email(evidence, phishing_eml_bytes)
    
    # Assert zero-width characters were stripped from body
    assert "\u200B" not in evidence.email.body_normalized
    
    # Assert hidden content was logged
    assert len(evidence.email.hidden_content_removed) > 0
    assert any("BENIGN CRAWLER TEXT" in log for log in evidence.email.hidden_content_removed)
    assert any("INVISIBLE DOM CLOAKING TEXT" in log for log in evidence.email.hidden_content_removed)
    
    # Assert findings were emitted
    finding_ids = [f.id for f in evidence.findings]
    assert "F-OBFUSCATION" in finding_ids
    assert "F-HIDDEN-DOM" in finding_ids


def test_reconstruction_clean_email_has_no_obfuscation(clean_eml_bytes, temp_storage):
    evidence = ingest_raw_email(clean_eml_bytes, "clean.eml", storage_dir=temp_storage)
    evidence = reconstruct_email(evidence, clean_eml_bytes)
    
    finding_ids = [f.id for f in evidence.findings]
    assert "F-OBFUSCATION" not in finding_ids
    assert "F-HIDDEN-DOM" not in finding_ids
    assert len(evidence.email.hidden_content_removed) == 0
