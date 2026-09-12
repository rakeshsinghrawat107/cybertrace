"""Tests for Module 7: 32-Dimensional Attack DNA & Campaign Similarity."""

import numpy as np
from src.modules.attack_dna import compute_attack_dna
from src.pipeline import ForensicPipeline


def test_attack_dna_vector_length_and_normalization(quishing_eml_bytes, temp_storage):
    pipeline = ForensicPipeline(storage_dir=temp_storage)
    evidence = pipeline.process(quishing_eml_bytes, "quish.eml", export_dossier=False)
    
    vec = evidence.attack_dna.vector
    assert len(vec) == 32
    
    # Assert unit L2 normalization
    norm = np.linalg.norm(vec)
    assert 0.99 <= norm <= 1.01


def test_attack_dna_matches_seeded_campaign(quishing_eml_bytes, temp_storage):
    pipeline = ForensicPipeline(
        storage_dir=temp_storage,
        seeded_db_path="tests/fixtures/seeded_campaigns.json"
    )
    evidence = pipeline.process(quishing_eml_bytes, "quish.eml", export_dossier=False)
    
    # Assert matches found
    matches = evidence.attack_dna.top_matches
    assert len(matches) >= 1
    
    top = matches[0]
    assert top.similarity_score >= 0.70
    assert len(top.drivers) >= 1
