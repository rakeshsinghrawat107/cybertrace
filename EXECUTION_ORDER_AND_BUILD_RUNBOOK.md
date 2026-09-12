# CyberTrace — Principal Architect Execution Order & Build Runbook

This document specifies the exact, step-by-step engineering execution order, quality gates, and verification criteria required to construct the CyberTrace platform from scratch. Every step must be executed in order without skipping or re-ordering phases to guarantee cryptographic integrity, modular decoupling, and zero test regressions.

---

## 1. Architectural Philosophy & Quality Invariants

Before executing any phase, the implementing engineer or autonomous agent must adhere to four immutable system invariants:

1. **The Preservation Invariant:**  
   The SHA-256 cryptographic digest of incoming `.eml` files must be computed directly on the unparsed network byte stream. Parsers and normalizers must never touch the byte stream prior to digest locking.
2. **The Truth-in-Attribution Invariant:**  
   Network metadata (GeoIP, ASN, ISP) represents *Infrastructure Association*, never personal criminal identity. Private IP addresses (RFC 1918) are skipped, and public hops are mapped to server data centers.
3. **The Zero-Hallucination Invariant:**  
   No narrative statement or human-readable explanation may be emitted by the system unless it directly cites a verified, programmatic finding token (`[F-XXX]`).
4. **The Non-Blocking Pipeline Invariant:**  
   The automated processing pipeline must complete all 9 analytical stages in **under 2.0 seconds**. User roles (SOC Analyst, Police IO, CISO) define RBAC authorization scopes on completed Evidence Objects; they do not form a sequential human approval bottleneck.

---

## 2. Phased Build Sequence & Execution Order

```text
[Phase 0: Environment] ──► [Phase 1: Domain Schemas] ──► [Phase 2: Ingestion & Storage]
                                                                   │
                                                                   ▼
[Phase 5: Legal Bundle] ◄── [Phase 4: Risk & Vector] ◄── [Phase 3: Forensic Modules]
         │
         ▼
[Phase 6: FastAPI REST] ──► [Phase 7: Synthetic Fixtures] ──► [Phase 8: Automated Tests]
```

### Phase 0: Toolchain & Dependency Verification

* **Objective:** Validate Python runtime, system shared libraries, and virtual environment isolation.
* **Prerequisites:** Python 3.11+ installed. On Linux, ensure `libzbar0` is installed (`apt-get install libzbar0`); on Windows/macOS, ensure the bundled wheel includes zbar binaries.
* **Commands:**
  ```powershell
  # Create and activate virtual environment
  python -m venv .venv
  .venv\Scripts\Activate.ps1

  # Upgrade package installer and install pinned dependencies
  python -m pip install --upgrade pip
  pip install -r requirements.txt
  ```
* **Exit Gate:** `python -c "import fastapi, pydantic, pyzbar, reportlab, PIL, numpy; print('Toolchain OK')"` executes with code `0`.

---

### Phase 1: Shared Domain Data Contract (`src/models/evidence_object.py`)

* **Objective:** Establish the Pydantic v2 data models that define the global state machine contract across all 9 modules.
* **Target Files:**
  * `src/models/__init__.py`
  * `src/models/evidence_object.py`
* **Models to Implement:**
  * `RiskBand` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  * `FindingCategory` (`OBSERVED_EVIDENCE`, `INFRASTRUCTURE_ASSOCIATION`, `INFERENCE`)
  * `ConfidenceLevel` (`LOW`, `MEDIUM`, `HIGH`, `VERIFIED`)
  * `RawEvidence` (object URI, SHA-256 digest, byte size, filename, MIME type)
  * `CustodyEvent` (event ID, actor, action, UTC timestamp, evidence hash)
  * `Finding` (finding ID, module source, claim, evidence refs, confidence)
  * `IndicatorSet` (URLs, domains, IPs, QR payload strings, attachments)
  * `EmailContent` (headers dict, raw body, normalized body, removed hidden strings, multipart mismatch flag)
  * `RiskAssessment` (composite score [0.0–1.0], band, component scores, weights, rationale)
  * `AttackDNA` (32-d L2 normalized vector, top similarity matches with driver breakdowns)
  * `NarrativeStep` (step number, statement, cited finding IDs)
  * `EvidenceObject` (root case object containing all the above plus custody log)
* **Exit Gate:** Schema can be imported and serialized to/from JSON with zero validation errors.

---

### Phase 2: Ingestion & Storage Subsystem (`src/modules/ingestion.py`)

* **Objective:** Implement the "Preservation Before Parsing" intake gateway.
* **Target Files:**
  * `src/modules/__init__.py`
  * `src/modules/ingestion.py`
* **Algorithm Requirements:**
  1. Generate standardized Case ID: `CT-2026-XXXXX`.
  2. Compute SHA-256 digest using `hashlib.sha256(raw_bytes).hexdigest()` directly on the incoming byte array.
  3. Write the exact, untouched byte stream to disk (`storage/{case_id}/raw.eml`).
  4. Instantiate the `EvidenceObject` and append the initial `CustodyEvent` (`action="RAW_INTAKE"`).
* **Exit Gate:** Any file ingested produces an exact SHA-256 match when re-read from storage.

---

### Phase 3: Adversarial Extraction & Forensic Modules

* **Objective:** Construct the deterministic reconstruction and extraction layers.
* **Target Files:**
  * `src/modules/reconstruction.py`
  * `src/modules/header_forensics.py`
  * `src/modules/auth_validator.py`
  * `src/modules/indicator_extractor.py`
* **Module 2 (Reconstruction):**
  * Parses MIME with `email.message_from_bytes`.
  * Detects multipart mismatches (clean plain text vs deceptive HTML).
  * Strips zero-width characters (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`, `\u2060`) and records them.
  * Applies `unicodedata.normalize("NFKC", ...)` to visible text to defang Cyrillic homoglyphs.
  * Inspects HTML DOM via `BeautifulSoup` for `display:none`, `visibility:hidden`, and `font-size:0`.
* **Module 3 (Header Forensics):**
  * Parses `Received` headers in **bottom-to-top** chronological order.
  * Checks for `Reply-To` vs `From` domain mismatches.
  * Flags display name brand impersonation (e.g., "State Bank of India" sent from a Gmail account).
* **Module 4 (Auth Validator):**
  * Parses `Authentication-Results`, `Received-SPF`, and `DKIM-Signature`.
  * Emits verified findings for SPF, DKIM, and DMARC alignment verdicts.
* **Module 5 (Indicators & QR Quishing Extractor):**
  * Extracts URLs from body text, `href`, and `src` attributes.
  * Scans inline and attached images in memory via `PIL.Image` and `pyzbar.decode`.
  * Emits finding `[F-QR-01]` if a QR code contains an actionable URL.
* **Exit Gate:** Synthetic obfuscated EML samples have all zero-width characters removed, hidden DOM text extracted, and QR payloads decoded without raising exceptions.

---

### Phase 4: Risk Scoring & Machine Intelligence Engines

* **Objective:** Implement transparent, explainable decision intelligence.
* **Target Files:**
  * `src/modules/risk_engine.py`
  * `src/modules/attack_dna.py`
  * `src/modules/attack_story.py`
* **Module 6 (Explainable Risk Engine):**
  * Computes composite score using the 8-component weighted formula:
    $$\text{Risk Score} = \sum_{i=1}^{8} (S_i \times W_i)$$
  * Enforces calibrated thresholds: $\ge 0.85 \implies \text{CRITICAL}$, $\ge 0.65 \implies \text{HIGH}$, $\ge 0.35 \implies \text{MEDIUM}$, $< 0.35 \implies \text{LOW}$.
* **Module 7 (Attack DNA & Vector Clustering):**
  * Populates the 32 structural feature dimensions according to the vector index specification.
  * Applies $L_2$ unit normalization: $V_{\text{norm}} = \frac{V}{\|V\|_2}$.
  * Computes cosine similarity against seeded campaign vectors: $\cos(\theta) = \frac{A \cdot B}{\|A\|_2 \|B\|_2}$.
  * Identifies primary mathematical drivers for clusters exceeding $0.70$ similarity.
* **Module 8 (Citation-Constrained Story):**
  * Assembles chronological incident narrative.
  * Programmatically inspects each sentence using regex: `r"\[(F-[A-Z0-9\-]+)\]"`.
  * Drops any statement that lacks a verified citation to an observed finding.
* **Exit Gate:** Risk scores strictly fall in $[0.0, 1.0]$, vector norms equal $1.000 \pm 0.001$, and story sentences contain $100\%$ verified finding citations.

---

### Phase 5: Legal Dossier & Section 63 BSA Packaging (`src/modules/dossier_exporter.py`)

* **Objective:** Assemble court-ready forensic packages compliant with Section 63 of Bharatiya Sakshya Adhiniyam, 2023.
* **Target Files:**
  * `src/modules/dossier_exporter.py`
* **Deliverables:**
  * **ReportLab PDF:** Case metadata, custody history, relay hop chronology, authentication verdicts, indicator summary, and pre-filled Section 63 BSA Technical Certificate.
  * **ZIP Bundle:** Contains `/raw/original_evidence.eml`, `/hashes/sha256_checksum.txt`, `/report/CyberTrace_Forensic_Report.pdf`, `/data/evidence_object.json`, and `/data/iocs.csv`.
* **Exit Gate:** ZIP package extracts cleanly, and the generated PDF renders properly formatted tables without truncation.

---

### Phase 6: Orchestration Pipeline & FastAPI REST API

* **Objective:** Wrap modules in a single-call linear pipeline and expose async HTTP endpoints.
* **Target Files:**
  * `src/pipeline.py`
  * `src/api/__init__.py`
  * `src/api/app.py`
* **Endpoints:**
  * `POST /cases`: Ingests multipart `.eml` upload, runs pipeline, returns `EvidenceObject`.
  * `GET /cases/{case_id}`: Returns stored JSON representation.
  * `POST /cases/{case_id}/verify`: Ingests re-uploaded `.eml`, validates SHA-256 against stored digest.
  * `GET /cases/{case_id}/report.pdf`: Streams the forensic PDF.
  * `GET /cases/{case_id}/evidence.zip`: Streams the complete Section 63 BSA bundle.
* **Exit Gate:** End-to-end HTTP request completes in under 2.0 seconds with status code `200 OK`.

---

### Phase 7: Synthetic Corpus Fixtures & Automated Test Suite

* **Objective:** Build reproducible test fixtures and achieve 100% automated test coverage.
* **Target Files:**
  * `tests/conftest.py`
  * `tests/fixtures/generate_synthetic_eml.py`
  * `tests/fixtures/seeded_campaigns.json`
  * `tests/test_ingestion.py`
  * `tests/test_reconstruction.py`
  * `tests/test_headers_and_auth.py`
  * `tests/test_qr_extractor.py`
  * `tests/test_risk_scoring.py`
  * `tests/test_attack_dna.py`
  * `tests/test_story_citations.py`
  * `tests/test_verify_endpoint.py`
  * `tests/test_adversarial_stress.py`
* **Commands to Run:**
  ```powershell
  # Generate synthetic test fixtures
  python tests/fixtures/generate_synthetic_eml.py

  # Run complete test harness
  pytest -v --durations=10
  ```
* **Exit Gate:** All unit and integration tests pass with 0 failures and 0 warnings.

---

## 3. Verification & Acceptance Checklist

| Checkpoint | Requirement | Verification Command | Expected Output |
|---|---|---|---|
| **Integrity** | Raw SHA-256 byte lock | `pytest tests/test_ingestion.py` | `PASSED` |
| **Evasion** | Zero-width character removal | `pytest tests/test_reconstruction.py` | `PASSED` |
| **Quishing** | In-memory QR code decoding | `pytest tests/test_qr_extractor.py` | `PASSED` |
| **Explainability** | Mathematical risk score bounds | `pytest tests/test_risk_scoring.py` | `PASSED` |
| **Clustering** | 32-d L2 vector cosine similarity | `pytest tests/test_attack_dna.py` | `PASSED` |
| **Safety** | Zero-hallucination regex guardrail | `pytest tests/test_story_citations.py` | `PASSED` |
| **Legal** | Section 63 BSA bundle packaging | `pytest tests/test_dossier_exporter.py` | `PASSED` |
| **Court Proof** | `/verify` cryptographic match | `pytest tests/test_verify_endpoint.py` | `PASSED` |
| **Robustness** | Adversarial mutation stability | `pytest tests/test_adversarial_stress.py` | `PASSED` |
| **Performance** | Pipeline latency < 2.0 seconds | Automated duration check | `< 2000ms` |
