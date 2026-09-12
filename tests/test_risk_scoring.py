"""Tests for Module 6: Explainable Mathematical Risk Engine."""

from src.models.evidence_object import RiskBand
from src.modules.risk_engine import COMPONENT_WEIGHTS, calculate_risk
from src.pipeline import ForensicPipeline


def test_component_weights_sum_to_one():
    total_weight = sum(COMPONENT_WEIGHTS.values())
    assert round(total_weight, 5) == 1.00000


def test_risk_scoring_phishing_sample(phishing_eml_bytes, temp_storage):
    pipeline = ForensicPipeline(storage_dir=temp_storage)
    evidence = pipeline.process(phishing_eml_bytes, "phishing.eml", export_dossier=False)
    
    assert 0.0 <= evidence.risk.score <= 1.0
    assert evidence.risk.band in (RiskBand.HIGH, RiskBand.CRITICAL)
    assert len(evidence.risk.rationale) > 0
    assert evidence.risk.component_scores["nlp_phishing_keyword"] > 0.0
    assert evidence.risk.component_scores["header_anomaly"] > 0.0


def test_risk_scoring_clean_sample(clean_eml_bytes, temp_storage):
    pipeline = ForensicPipeline(storage_dir=temp_storage)
    evidence = pipeline.process(clean_eml_bytes, "clean.eml", export_dossier=False)
    
    assert evidence.risk.score < 0.35
    assert evidence.risk.band == RiskBand.LOW
