"""Adversarial Stress & Mutation Resilience Testing for CyberTrace."""

import email
from email import policy
from email.message import EmailMessage
from src.pipeline import ForensicPipeline


def test_adversarial_mutations_score_stability(phishing_eml_bytes, temp_storage):
    """Applies whitespace injection and homoglyph mutations and asserts risk score stability (<= 10% delta)."""
    pipeline = ForensicPipeline(storage_dir=temp_storage)
    
    # 1. Baseline unmutated run
    base_evidence = pipeline.process(phishing_eml_bytes, "base.eml", export_dossier=False)
    base_score = base_evidence.risk.score
    
    # 2. Mutation 1: Excessive whitespace padding and newline injections in body
    mutated_bytes_1 = phishing_eml_bytes.replace(
        b"Dear Customer",
        b"   \n\n\t  Dear Customer \t \n\n   "
    )
    ev_mut1 = pipeline.process(mutated_bytes_1, "mut1.eml", export_dossier=False)
    score_1 = ev_mut1.risk.score
    
    # 3. Mutation 2: Cyrillic homoglyph replacement ('a' -> Cyrillic 'а' \u0430)
    mutated_bytes_2 = phishing_eml_bytes.replace(b"Suspended", "Susp\u0430nded".encode("utf-8"))
    ev_mut2 = pipeline.process(mutated_bytes_2, "mut2.eml", export_dossier=False)
    score_2 = ev_mut2.risk.score
    
    # Delta should be <= 10% (0.10)
    assert abs(score_1 - base_score) <= 0.10, f"Whitespace mutation score delta exceeded: {abs(score_1 - base_score)}"
    assert abs(score_2 - base_score) <= 0.10, f"Homoglyph mutation score delta exceeded: {abs(score_2 - base_score)}"
    assert ev_mut1.risk.band == base_evidence.risk.band
    assert ev_mut2.risk.band == base_evidence.risk.band
