# CyberTrace — AI-Powered Email Threat Detection & Forensic Platform

[![Test Suite](https://img.shields.io/badge/pytest-17%20passed%2C%200%20failed-brightgreen.svg)](./tests)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](./requirements.txt)
[![SIH 2026](https://img.shields.io/badge/Smart%20India%20Hackathon-2026-orange.svg)](./ARCHITECTURE_DECISION_RECORDS_ADR.md)
[![Legal Compliance](https://img.shields.io/badge/Section%2063%20BSA-2023%20Compliant-purple.svg)](./src/modules/dossier_exporter.py)

**CyberTrace** is an evidence-oriented email threat detection, protocol forensics, and court-admissible digital intelligence platform designed for **Smart India Hackathon 2026**.

It ingest untrusted `.eml` files, cryptographically locks their SHA-256 digest on raw network bytes (Zero Hash Drift), reconstructs adversarial obfuscations (zero-width Unicode, homoglyphs, CSS cloaking), extracts quishing QR payloads via in-memory computer vision, scores threats via an explainable 8-component mathematical formula, computes a 32-dimensional "Attack DNA" vector, and exports court-ready forensic dossiers compliant with **Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 (BSA)**.

---

## 1. Directory Structure

```text
cybertrace/
├── .gitignore                             # Python, venv, cache, and artifact exclusions
├── README.md                              # Main overview, architecture, API & setup guide
├── CHANGELOG.md                           # Autonomous architectural build & engineering log
├── requirements.txt                       # Pinned production & test dependencies
├── ARCHITECTURE_DECISION_RECORDS_ADR.md   # Architectural justifications & legal citations
├── EXECUTION_ORDER_AND_BUILD_RUNBOOK.md   # Phased engineering runbook & quality gates
├── MASTER_READY_TO_GO_BUILD_PROMPT.md     # Master architectural design specification
├── src/
│   ├── __init__.py
│   ├── models/                            # Pydantic v2 Data Contracts
│   │   ├── __init__.py
│   │   └── evidence_object.py             # Global EvidenceObject, Finding, RiskAssessment, AttackDNA, Custody
│   ├── modules/                           # 9 Forensic & Analytical Engines
│   │   ├── __init__.py
│   │   ├── ingestion.py                   # Module 1: Safe intake, zero hash drift, SHA-256 locking
│   │   ├── reconstruction.py              # Module 2: Zero-width strip, NFKC homoglyphs, CSS DOM hiding
│   │   ├── header_forensics.py            # Module 3: Bottom-up Received hops, brand & Reply-To anomalies
│   │   ├── auth_validator.py              # Module 4: SPF, DKIM, DMARC verdict & domain alignment
│   │   ├── indicator_extractor.py         # Module 5: URL/domain canonicalization & dual-engine QR CV
│   │   ├── risk_engine.py                 # Module 6: 8-component explainable mathematical risk formula
│   │   ├── attack_dna.py                  # Module 7: 32-dimensional L2 feature vector & cosine similarity
│   │   ├── attack_story.py                # Module 8: Citation-constrained programmatic incident narrative
│   │   └── dossier_exporter.py            # Module 9: ReportLab PDF report & Section 63 BSA ZIP bundle
│   ├── pipeline.py                        # Linear DAG orchestrator running all 9 stages (< 1.7s)
│   └── api/
│       ├── __init__.py
│       └── app.py                         # FastAPI service (/cases, /verify, /report.pdf, /evidence.zip)
├── tests/
│   ├── __init__.py
│   ├── conftest.py                        # Pytest fixtures and FastAPI test client setup
│   ├── fixtures/                          # Synthetic adversarial test email samples
│   │   ├── __init__.py
│   │   ├── generate_synthetic_eml.py      # Automated generator for clean, spoofed, and quishing EMLs
│   │   └── seeded_campaigns.json          # Seeded historical 32-d Attack DNA campaign vectors
│   ├── test_ingestion.py                  # Validates byte preservation, hash immutability & custody
│   ├── test_reconstruction.py             # Validates U+200B removal, homoglyphs & CSS hiding extraction
│   ├── test_headers_and_auth.py           # Validates hop chronological ordering & auth verdicts
│   ├── test_qr_extractor.py               # Validates in-memory computer vision QR quishing detection
│   ├── test_risk_scoring.py               # Validates 8-weight formula & score band thresholds
│   ├── test_attack_dna.py                 # Validates vector construction & cosine similarity matching
│   ├── test_story_citations.py            # Validates zero-hallucination [F-XXX] citation filter
│   ├── test_verify_endpoint.py            # Validates /verify cryptographic proof endpoint
│   └── test_adversarial_stress.py         # Validates stability under mutations (<10% score variance)
└── data/
    └── .gitkeep                           # Local case storage directory (raw EMLs & generated legal ZIPs)
```

---

## 2. The 6 Core Innovations

1. **Preservation Before Parsing (Zero Hash Drift):**  
   Streaming unparsed network bytes to storage and locking the SHA-256 digest *before* any MIME parser touches the file, provable via a live `/verify` endpoint.
2. **Adversarial MIME & DOM De-Obfuscation:**  
   Multi-pass stripping of zero-width Unicode characters (`U+200B`), NFKC homoglyph normalization, and BeautifulSoup CSS DOM hiding extraction (`display:none`, `font-size:0`, contrast camouflage).
3. **Native Multimodal QR Quishing Extraction:**  
   Dual-engine computer vision scanning via `pyzbar` and OpenCV `QRCodeDetector` on all attached/inline images in memory without writing untrusted files to disk.
4. **Zero-Hallucination Programmatic AI Guardrails:**  
   Generative narrative models receive only structured finding tokens (`[F-001]`). Programmatic regex AST validator rejects any statement lacking verified citations.
5. **Multi-Signal "Attack DNA" Vector Clustering:**  
   32-dimensional normalized structural feature vector ($L_2$ unit length) matched against historical campaigns using cosine distance, exposing the exact mathematical drivers.
6. **Built-in Section 63 BSA 2023 Digital Evidence Packaging:**  
   One-click generation of a court-ready evidence ZIP bundle: untouched `.eml`, SHA-256 checksum, custody audit log, IoC CSV, and an audit-ready PDF with a pre-filled Section 63 BSA technical certificate.

---

## 3. Quickstart: Installation & Running

### Prerequisites
- Python 3.11+
- Git

### Setup Virtual Environment
```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install production and test dependencies
pip install -r requirements.txt
```

### Launch the REST API
```powershell
uvicorn src.api.app:app --host 127.0.0.1 --port 8000 --reload
```
Interactive Swagger API documentation will be available at: `http://127.0.0.1:8000/docs`.

### Run the Automated Test Harness
```powershell
pytest -v
```
All **17 tests pass with 0 failures** across the 9 forensic modules, the REST API, and adversarial stress tests in under **1.5 seconds**.

---

## 4. API Endpoints Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/cases` | Ingests `.eml` multipart upload, seals hash, executes 9 modules, returns `EvidenceObject`. |
| `GET` | `/cases/{id}` | Retrieves stored forensic `EvidenceObject` JSON. |
| `POST` | `/cases/{id}/verify` | Cryptographic SHA-256 integrity re-check proving Zero Hash Drift under Section 63 BSA. |
| `GET` | `/cases/{id}/report.pdf` | Downloads court-admissible ReportLab PDF forensic report with legal certificate. |
| `GET` | `/cases/{id}/evidence.zip` | Downloads complete tamper-evident Section 63 BSA ZIP bundle. |
| `GET` | `/health` | Service health status check. |

---

## 5. Architectural & Build Logs

For complete engineering logs, OOP/SOLID architectural notes, and verification records, consult [`CHANGELOG.md`](./CHANGELOG.md) and [`ARCHITECTURE_DECISION_RECORDS_ADR.md`](./ARCHITECTURE_DECISION_RECORDS_ADR.md).
