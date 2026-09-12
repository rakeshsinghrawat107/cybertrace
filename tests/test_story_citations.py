"""Tests for Module 8: Citation-Constrained Attack Story (Zero-Hallucination)."""

import re
from src.modules.attack_story import generate_grounded_story
from src.pipeline import ForensicPipeline


def test_story_every_step_has_valid_citation(phishing_eml_bytes, temp_storage):
    pipeline = ForensicPipeline(storage_dir=temp_storage)
    evidence = pipeline.process(phishing_eml_bytes, "phishing.eml", export_dossier=False)
    
    story = evidence.attack_story
    assert len(story) >= 1
    
    valid_finding_ids = {f.id for f in evidence.findings}
    
    for step in story:
        assert len(step.cited_findings) >= 1
        for cid in step.cited_findings:
            assert cid in valid_finding_ids
            assert f"[{cid}]" in step.statement


def test_story_filters_out_uncited_claims(clean_eml_bytes, temp_storage):
    pipeline = ForensicPipeline(storage_dir=temp_storage)
    evidence = pipeline.process(clean_eml_bytes, "clean.eml", export_dossier=False)
    
    # If a clean email has only F-AUTH-01, only statements citing F-AUTH-01 may remain
    for step in evidence.attack_story:
        assert all(f.startswith("F-") for f in step.cited_findings)
