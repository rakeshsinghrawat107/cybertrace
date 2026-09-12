# CyberTrace — Master Production Build Prompt (Autonomous Execution Ready)

> **Copy and paste the entire block below into an autonomous coding agent (Antigravity, Cursor, Claude 3.7 Sonnet, or Copilot) to generate the complete, production-grade CyberTrace MVP codebase and automated testing harness with zero errors.**

---

```markdown
# MISSION BRIEF: BUILD CYBERTRACE FORENSIC PLATFORM (PRODUCTION MVP)

You are tasked with engineering **CyberTrace**, an evidence-oriented email threat detection and forensic intelligence platform for Smart India Hackathon 2026 (Problem Statement: AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform).

The goal is to build a high-integrity, modular Python application that ingests suspicious `.eml` files, cryptographically seals them, reconstructs adversarial obfuscations, extracts indicators (including embedded QR codes), scores risks with an explainable formula, clusters attacks using multi-signal "Attack DNA", and exports court-ready forensic dossiers compliant with Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 (BSA).

Follow the exact technical blueprints, contracts, data schemas, algorithms, and testing requirements below to build the software end-to-end with 100% test pass rate.

---

## 1. COMPETITIVE LANDSCAPE & FLAWS IN EXISTING TECHNOLOGIES

To ensure CyberTrace delivers genuine novelty, the implementation must explicitly address the architectural failures of the five prevailing tool categories:

1. **Secure Email Gateways (SEGs — Proofpoint, Mimecast, SpamAssassin):**
   * *Architectural Flaw:* Synchronous perimeter-only inline filtering (binary pass/drop). Highly vulnerable to adversarial evasions: zero-width Unicode injection (`U+200B`), CSS DOM hiding (`display:none`), and image-only QR quishing payloads.
   * *Forensic Flaw:* Zero post-detection investigation, zero custody tracking, and zero legal packaging for prosecution.

2. **Multi-Engine File & URL Scanners (VirusTotal, URLScan.io):**
   * *Architectural Flaw:* Isolated file or hash lookup without RFC 5322 MIME awareness. Cannot reconstruct Received relay hops or evaluate SPF/DKIM/DMARC alignment.
   * *Privacy & Legal Flaw:* Public uploads expose sensitive institutional data to public threat feeds, destroying legal chain of custody.

3. **Threat Intelligence Platforms (MISP, OpenCTI):**
   * *Architectural Flaw:* Manual threat-tagging repository. Does not automate adversarial de-obfuscation, calculate explainable risk scores from raw `.eml` files, or cluster campaigns across multi-dimensional structural features.
   * *Operational Flaw:* Requires dedicated security engineers to populate attributes manually.

4. **Commercial Phishing Triage (Cofense Triage, PhishTool):**
   * *Architectural Flaw:* "Parse-Then-Save" byte mutation. Loading raw emails into high-level objects silently converts line endings (`\r\n` to `\n`), re-folds headers, and alters encodings, breaking the SHA-256 hash digest.
   * *Legal Flaw:* Closed, proprietary black-box scoring with zero Section 63 BSA legal compliance.

5. **Generic LLMs & AI Wrappers (ChatGPT, Microsoft Copilot):**
   * *Architectural Flaw:* High hallucination rate. When prompted with unconstrained email text, models invent non-existent IPs, false attacker motives, and fictitious malware names.
   * *Legal Flaw:* Uncited, non-deterministic output that crumbles under legal cross-examination in court.

---

## 2. THE 6 CORE ARCHITECTURAL INNOVATIONS (WHAT WE DO DIFFERENTLY)

The software must implement these 6 concrete technical breakthroughs:

* **Innovation 1: Preservation Before Parsing (Zero Hash Drift):**  
  Stream raw network socket bytes directly to encrypted storage (MinIO) and lock the SHA-256 digest on the unparsed byte buffer *before* any parser touches the file. Provide a live `/verify` endpoint to mathematically prove zero byte drift.

* **Innovation 2: Adversarial MIME & DOM De-Obfuscation:**  
  Multi-pass lexical cleaner stripping invisible zero-width Unicode characters (`U+200B`, `U+200C`, `U+200D`, `U+FEFF`, `U+2060`), normalizing lookalike Cyrillic homoglyphs via NFKC, and extracting CSS hidden text (`display:none`, `visibility:hidden`, `font-size:0`, color matching background).

* **Innovation 3: Native Multimodal QR Quishing Extraction:**  
  Automated computer vision extraction using `pyzbar` and `Pillow` on all attached and inline images in memory (without executing active content or writing files to disk).

* **Innovation 4: Zero-Hallucination AI (Citation-Constrained Storytelling):**  
  Generative models never see raw email text. They receive only structured, verified JSON finding tokens (`[F-001]`). A programmatic regex validator (`r"\[(F-[A-Z0-9\-]+)\]"`) inspects every sentence: any statement lacking a valid citation is deleted.

* **Innovation 5: Multi-Signal "Attack DNA" Vector Clustering:**  
  Extract a 32-dimensional normalized structural feature vector ($L_2$ normalized) and query historical campaigns in PostgreSQL using `pgvector`'s cosine distance operator (`<=>`), exposing the exact mathematical drivers behind campaign clusters.

* **Innovation 6: Built-in Section 63 BSA 2023 (Section 65B) Legal Packaging:**  
  One-click export of a tamper-evident ZIP bundle: untouched `.eml`, SHA-256 checksum, custody audit log, IoC CSV, and an audit-ready PDF with a pre-filled Section 63 BSA technical certificate annexure ready for the investigating officer's signature.

---

## 3. TRUTH-IN-ATTRIBUTION & NETWORK FORENSIC INVARIANTS

The software must enforce strict technical accuracy regarding IP Geolocation and Network Attribution:

1. **Network Infrastructure Association vs. Physical Location:**
   * GeoIP resolves the physical data center or ISP Point of Presence (PoP) hosting the mail relay or web server.
   * GeoIP does **NOT** represent the physical living room of the human attacker. Attackers operate through VPNs, compromised VPS instances, Tor exit nodes, or open proxies.
   * All GeoIP outputs must be labeled: **"Network Infrastructure Association"**, never "Physical Attacker Location".

2. **Private IP Handling:**
   * Relay headers containing private IP addresses (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and RFC 6598 CGNAT `100.64.0.0/10`) must be tagged as internal hops and excluded from public ASN lookups.

3. **ISP Requisition Preparation (Section 94 BNSS / Section 91 CrPC):**
   * The legal bundle must format the Originating Egress IP, Port, Timestamp (UTC), and ISP ASN into a standardized requisition template for Law Enforcement to serve legal notices to Internet Service Providers to obtain subscriber identity records.

---

## 4. THE 4 EPISTEMOLOGICAL DATA TIERS & INVARIANTS

Every data field in the system must be strictly classified into one of four tiers:

* **Observed Evidence:** Immutable facts directly in the raw byte stream (raw SHA-256, literal headers, URLs, QR payload bytes). Bounded by cryptographic proof.
* **Infrastructure Association:** Contextual network metadata (ASN, ISP, server GeoIP, Tor exit status). Strictly labeled as *association*, never direct human personal attribution.
* **System Inference:** Algorithmic calculations (Risk Score 0.88, Phishing Probability, Attack DNA Similarity). Must expose underlying mathematical weights.
* **Human Conclusion:** Legal or operational decisions (Incident disposition, Section 63 BSA certificate signing). Solely the authority of the human investigator.

---

## 5. USER ROLES & RBAC PERMISSION MATRIX

The system must support 5 operational roles without slowing down the automated pipeline:
* **The 90-Second MTTI Guarantee:** The automated processing pipeline executes all 9 modules in **under 2 seconds** asynchronously. User roles do NOT form a sequential human approval chain; they represent RBAC access tiers on the pre-computed forensic case.

* **Tier-1 SOC Analyst:** Ingests `.eml`, reviews composite risk score (0–100) and visual de-obfuscation diff, confirms or dismisses alerts in under 90 seconds.
* **Senior Forensic Analyst / Incident Responder:** Deep hop graph analysis, Attack DNA campaign clustering, technical finding annotation, and IoC blocklist exports.
* **Cyber Police / Investigating Officer (IO):** Executes `/verify` hash integrity re-checks, downloads Section 63 BSA legal bundles, and signs technical certificates.
* **CISO / SOC Manager:** Monitors institutional MTTI (Mean Time to Investigate), exports STIX 2.1 threat feeds, and oversees inter-agency coordination.
* **Platform Administrator:** Manages offline binary database updates (MaxMind `.mmdb`), storage retention, and system health.

| Permission / Capability | Tier-1 Analyst | Senior Forensic IR | Police / IO | CISO / Manager | Admin |
|---|:---:|:---:|:---:|:---:|:---:|
| **Upload `.eml` & View Score** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Inspect De-obfuscation Diff** | ✅ | ✅ | ✅ | ⚠️ Summary | ❌ |
| **Attack DNA Vector Clustering** | ❌ | ✅ | ✅ | ⚠️ High-level | ❌ |
| **Execute `/verify` Hash Proof** | ❌ | ✅ | ✅ | ❌ | ✅ |
| **Download Section 63 BSA ZIP** | ❌ | ✅ | ✅ | ❌ | ❌ |
| **Export Firewall IoCs (CSV/STIX)**| ❌ | ✅ | ❌ | ✅ | ❌ |
| **Update Offline GeoIP Databases** | ❌ | ❌ | ❌ | ❌ | ✅ |

---

## 6. END-TO-END PIPELINE PROCESSING DAG

The processing flow must follow this strict linear Directed Acyclic Graph (DAG):

```text
[Raw EML Upload]
       │
       ▼
[Module 1: Safe Ingestion] ──► SHA-256 Digest & Raw Storage (MinIO)
       │
       ▼
[Module 2: Reconstruction] ──► MIME Parse, Zero-Width Strip, NFKC Homoglyphs, CSS Hide
       │
       ▼
[Module 3: Header Forensics] ──► Bottom-to-Top Received Hops, From/Reply-To Check
       │
       ▼
[Module 4: Auth Validator] ──► SPF, DKIM, DMARC Verdicts & Alignment
       │
       ▼
[Module 5: Indicators & QR] ──► URL Canonicalization & Pyzbar Quishing CV Extraction
       │
       ▼
[Module 6: Risk Engine] ──► 8-Component Linear Formula (Weights sum to 1.0)
       │
       ▼
[Module 7: Attack DNA] ──► 32-d Normalized Vector & pgvector Cosine Match
       │
       ▼
[Module 8: Attack Story] ──► Regex-Validated Finding-Cited Incident Narrative
       │
       ▼
[Module 9: Dossier Exporter] ──► ReportLab PDF & Section 63 BSA Sealed ZIP Bundle
```

---

## 7. RUNTIME, DEPENDENCIES & PRODUCTION STANDARDS

* **Runtime:** Python 3.11+
* **Framework:** FastAPI (stateless, async ASGI service) + Uvicorn
* **Core Dependencies (`requirements.txt`):**
  * `fastapi>=0.115.0`
  * `uvicorn[standard]>=0.30.0`
  * `pydantic>=2.8.0`
  * `python-multipart>=0.0.9`
  * `beautifulsoup4>=4.12.0`
  * `lxml>=5.2.0`
  * `pillow>=10.4.0`
  * `pyzbar>=0.1.9`
  * `reportlab>=4.2.0`
  * `qrcode[pil]>=7.4.2`
  * `numpy>=1.26.0`
  * `pytest>=8.3.0`
  * `httpx>=0.27.0`
* **Performance Budget:** Machine pipeline execution in **under 2.0 seconds** per 50KB email.
* **Architectural Standard:** The "Evidence Object" contract. Modules take the global Evidence Object, apply deterministic or contextual analysis, append structured `Finding` items (with IDs `F-001`, `F-002`), log custody events, and write the state back.

---

## 8. REPOSITORY & FILE STRUCTURE TO CREATE

```text
cybertrace/
├── requirements.txt
├── README.md
├── src/
│   ├── __init__.py
│   ├── models/
│   │   ├── __init__.py
│   │   └── evidence_object.py        # Pydantic schemas: EvidenceObject, Finding, RiskAssessment, etc.
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── ingestion.py              # Raw streaming, SHA-256 digest, case ID, custody initialization
│   │   ├── reconstruction.py         # MIME walk, zero-width stripper, homoglyph NFKC, CSS DOM inspector
│   │   ├── header_forensics.py       # Bottom-to-top Received hops, From/Reply-To/Return-Path checks
│   │   ├── auth_validator.py         # Authentication-Results parser (SPF, DKIM, DMARC alignment)
│   │   ├── indicator_extractor.py    # URL canonicalizer, redirect tracer, pyzbar QR decoder
│   │   ├── risk_engine.py            # Fixed 8-component mathematical risk formula & bands
│   │   ├── attack_dna.py             # 32-dimensional feature vector builder & cosine similarity engine
│   │   ├── attack_story.py           # Citation-enforced chronological narrative generator
│   │   └── dossier_exporter.py       # ReportLab PDF generator & Section 63 BSA ZIP bundle packager
│   ├── pipeline.py                   # Orchestrator running modules sequentially over an EvidenceObject
│   └── api/
│       ├── __init__.py
│       └── app.py                    # FastAPI app: /cases, /cases/{id}, /cases/{id}/verify, /cases/{id}/export
└── tests/
    ├── __init__.py
    ├── conftest.py                   # Pytest fixtures and test client setup
    ├── fixtures/
    │   ├── __init__.py
    │   ├── generate_synthetic_eml.py # Creates clean, BEC spoof, quishing, and zero-width .eml samples
    │   └── seeded_campaigns.json     # Seeded campaign feature vectors for Attack DNA similarity tests
    ├── test_ingestion.py             # Verifies byte preservation, SHA-256 digest, and custody log
    ├── test_reconstruction.py        # Verifies U+200B stripping, NFKC normalization, and CSS hiding detection
    ├── test_headers_and_auth.py      # Verifies hop sequencing and SPF/DKIM/DMARC verdicts
    ├── test_qr_extractor.py          # Verifies QR extraction from image attachments
    ├── test_risk_scoring.py          # Verifies mathematical boundary calculations and risk bands
    ├── test_attack_dna.py            # Verifies cosine similarity against seeded campaigns
    ├── test_story_citations.py       # Verifies that uncited hallucinated sentences are rejected
    ├── test_verify_endpoint.py       # Verifies cryptographic SHA-256 match on re-upload
    └── test_adversarial_stress.py    # Verifies detector stability under adversarial mutations
```

---

## 9. DATA CONTRACT: GLOBAL EVIDENCE OBJECT (`src/models/evidence_object.py`)

Implement strict Pydantic v2 models representing the system's global contract:

```python
from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime

class RiskBand(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class FindingCategory(str, Enum):
    OBSERVED_EVIDENCE = "OBSERVED_EVIDENCE"
    INFRASTRUCTURE_ASSOCIATION = "INFRASTRUCTURE_ASSOCIATION"
    INFERENCE = "INFERENCE"

class ConfidenceLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERIFIED = "VERIFIED"

class RawEvidence(BaseModel):
    object_uri: str
    sha256: str
    size_bytes: int
    original_filename: str
    mime_type: str = "message/rfc822"

class CustodyEvent(BaseModel):
    event_id: str
    actor: str
    action: str
    timestamp: datetime
    evidence_hash: str

class Finding(BaseModel):
    id: str                                  # e.g., "F-001"
    module: str                              # e.g., "reconstruction", "header_forensics"
    category: FindingCategory
    claim: str
    evidence_refs: List[str]                 # e.g., ["H-002", "U-001"]
    confidence: ConfidenceLevel

class IndicatorSet(BaseModel):
    urls: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    qr_payloads: List[str] = Field(default_factory=list)
    attachments: List[Dict[str, Any]] = Field(default_factory=list)

class EmailContent(BaseModel):
    headers: Dict[str, Any] = Field(default_factory=dict)
    body_raw: str = ""
    body_normalized: str = ""
    hidden_content_removed: List[str] = Field(default_factory=list)
    multipart_mismatch: bool = False

class RiskAssessment(BaseModel):
    score: float = 0.0                       # Range [0.0, 1.0]
    band: RiskBand = RiskBand.LOW
    component_scores: Dict[str, float] = Field(default_factory=dict)
    component_weights: Dict[str, float] = Field(default_factory=dict)
    rationale: str = ""

class SimilarityMatch(BaseModel):
    case_id: str
    similarity_score: float
    drivers: List[str]

class AttackDNA(BaseModel):
    vector: List[float] = Field(default_factory=list)
    top_matches: List[SimilarityMatch] = Field(default_factory=list)

class NarrativeStep(BaseModel):
    step_number: int
    statement: str
    cited_findings: List[str]

class EvidenceObject(BaseModel):
    case_id: str
    ingested_at: datetime
    processing_status: str = "QUEUED"
    evidence: RawEvidence
    email: EmailContent = Field(default_factory=EmailContent)
    indicators: IndicatorSet = Field(default_factory=IndicatorSet)
    findings: List[Finding] = Field(default_factory=list)
    risk: RiskAssessment = Field(default_factory=RiskAssessment)
    attack_dna: AttackDNA = Field(default_factory=AttackDNA)
    attack_story: List[NarrativeStep] = Field(default_factory=list)
    chain_of_custody: List[CustodyEvent] = Field(default_factory=list)
```

---

## 10. EXACT 32-DIMENSIONAL "ATTACK DNA" FEATURE INDEX SPECIFICATION

The vector builder in `src/modules/attack_dna.py` must populate each index according to this exact structural definition:

| Vector Index | Feature Dimension | Normalization / Value Mapping | Rationale |
|:---:|---|---|---|
| **0** | Relay Hop Count | $\min(H / 20.0, 1.0)$ | Transit path complexity |
| **1** | Recipient Count | $\min(R / 10.0, 1.0)$ | Spray vs spear-phishing |
| **2** | Subject Character Length | $\min(L / 250.0, 1.0)$ | Urgency header padding |
| **3** | Body Character Length | $\min(C / 10000.0, 1.0)$ | Payload size volume |
| **4** | Total Header Count | $\min(H_{tot} / 50.0, 1.0)$ | Structural envelope footprint |
| **5** | Multipart Boundary Anomaly | `1.0` if malformed boundary else `0.0` | Parser evasion tactic |
| **6** | Missing Message-ID | `1.0` if absent else `0.0` | Non-standard mailer |
| **7** | Display Name Brand Impersonation | `1.0` if brand spoof detected else `0.0` | Social engineering hook |
| **8** | Zero-Width Char Count (`U+200B` etc.) | $\min(Z / 50.0, 1.0)$ | NLP bypass evasion |
| **9** | Cyrillic/NFKC Homoglyph Count | $\min(G / 20.0, 1.0)$ | Visual domain spoofing |
| **10** | CSS Hidden Tags (`display:none`) | $\min(T / 10.0, 1.0)$ | DOM cloaking |
| **11** | CSS Tiny Font (`font-size:0`) | $\min(F / 10.0, 1.0)$ | Crawler text stuffing |
| **12** | Same-color Foreground/Background | `1.0` if hidden text else `0.0` | Visual camouflage |
| **13** | Base64/Script Tag Present | `1.0` if present else `0.0` | Active payload injection |
| **14** | Punycode Domain (`xn--`) | `1.0` if present else `0.0` | Internationalized domain spoof |
| **15** | Multipart Text/HTML Mismatch | `1.0` if plain/HTML diverge else `0.0` | SEG desynchronization |
| **16** | Total Extracted URL Count | $\min(U / 20.0, 1.0)$ | Link density |
| **17** | Unique Domains Count | $\min(D / 10.0, 1.0)$ | External infrastructure spread |
| **18** | IP-Literal URL Present | `1.0` if raw IP used else `0.0` | Unregistered staging host |
| **19** | QR Code Payload Present | `1.0` if QR detected else `0.0` | Quishing attack indicator |
| **20** | QR Target URL Redirection | `1.0` if redirector else `0.0` | Multi-hop evasion |
| **21** | Total Attachment Count | $\min(A / 5.0, 1.0)$ | File carrier volume |
| **22** | High-Risk Extension (.exe, .scr, .iso) | `1.0` if risky file else `0.0` | Malicious payload |
| **23** | Office Macro Extension (.docm, .xlsm) | `1.0` if macro file else `0.0` | Weaponized document |
| **24** | SPF Verdict Numeric | Pass=0.0, Neutral=0.3, Fail=1.0, None=0.5 | Domain authentication |
| **25** | DKIM Verdict Numeric | Pass=0.0, Fail=1.0, None=0.5 | Cryptographic signature |
| **26** | DMARC Verdict Numeric | Pass=0.0, Fail=1.0, None=0.5 | Policy alignment |
| **27** | Reply-To Domain Mismatch | `1.0` if mismatched else `0.0` | Out-of-band exfiltration |
| **28** | Return-Path Mismatch | `1.0` if mismatched else `0.0` | Bounce redirection |
| **29** | Originating ASN Infrastructure Risk | Bulletproof/Tor=1.0, Cloud=0.6, ISP=0.1 | Egress network reputation |
| **30** | NLP Credential Harvesting Score | Continuous float [0.0, 1.0] | Phishing keyword intent |
| **31** | NLP Urgent Financial Threat Score | Continuous float [0.0, 1.0] | Coercive action intent |

*After building the 32 raw values, compute the unit length $L_2$ normalized vector: $V_{\text{norm}} = \frac{V}{\|V\|_2}$.*

---

## 11. MODULE IMPLEMENTATION SPECIFICATIONS

### Module 1: Safe Intake & Hashing (`src/modules/ingestion.py`)

* **Function Signature:** `def ingest_raw_email(file_bytes: bytes, filename: str, storage_dir: str) -> EvidenceObject`
* **Algorithm:**
  1. Generate `case_id`: `f"CT-2026-{uuid.uuid4().hex[:5].upper()}"`.
  2. Compute SHA-256 directly on the unparsed `file_bytes` using `hashlib.sha256(file_bytes).hexdigest()`. Do NOT parse or normalize before computing the digest.
  3. Write raw bytes to `{storage_dir}/{case_id}/raw.eml`.
  4. Create initial `CustodyEvent`: `{event_id: "EV-001", actor: "SYSTEM", action: "RAW_INTAKE", timestamp: datetime.utcnow(), evidence_hash: sha256}`.
  5. Return initialized `EvidenceObject`.

### Module 2: Adversarial Email Reconstruction (`src/modules/reconstruction.py`)

* **Function Signature:** `def reconstruct_email(evidence: EvidenceObject, raw_bytes: bytes) -> EvidenceObject`
* **Algorithm:**
  1. Parse MIME tree with `email.message_from_bytes(raw_bytes)`.
  2. Extract `text/plain` and `text/html` parts. If both exist, compare content length and URL counts. If plain text is clean but HTML contains links, set `multipart_mismatch = True` and emit Finding `[F-MIME]`.
  3. **Zero-Width Character Stripping:**
     * Target Unicode categories `Cf` and codepoints: `\u200B` (zero-width space), `\u200C` (zero-width non-joiner), `\u200D` (zero-width joiner), `\uFEFF` (BOM), `\u2060` (word joiner).
     * Count matches, log them in `hidden_content_removed`, and strip them from the subject and body. If count > 0, emit Finding `[F-OBFUSCATION]` with category `OBSERVED_EVIDENCE`.
  4. **Homoglyph & Punycode Normalization:**
     * Apply `unicodedata.normalize("NFKC", text)` to visible body text.
     * Identify any `xn--` punycode domains and decode via `idna.decode()`.
  5. **CSS DOM Hidden Extraction:**
     * Parse HTML with `BeautifulSoup(html_content, "lxml")`.
     * Inspect elements for styles: `display:\s*none`, `visibility:\s*hidden`, `font-size:\s*0`, or font color matching background color (e.g. `#ffffff` text on `#ffffff` bg).
     * Extract hidden text, append to `hidden_content_removed`, strip from rendered HTML, and emit Finding `[F-HIDDEN-DOM]`.
  6. Store result in `evidence.email.body_normalized`.

### Module 3: Header Forensics & Received Chain (`src/modules/header_forensics.py`)

* **Function Signature:** `def analyze_headers(evidence: EvidenceObject, msg: email.message.Message) -> EvidenceObject`
* **Algorithm:**
  1. Extract all `Received` headers. Reverse the list to parse **bottom-to-top** (chronological transit from sender to destination MX).
  2. For each hop, regex-parse: sender host/IP (`from`), recipient host (`by`), protocol (`with`), and timestamp.
  3. Check anomalies:
     * `Reply-To` domain differs from `From` header domain $\rightarrow$ Emit Finding `[F-HDR-01]`.
     * `From` display name contains a recognized brand (e.g. "PayPal Support") but sending domain is untrusted $\rightarrow$ Emit Finding `[F-HDR-02]`.
     * Missing `Message-ID` or invalid syntax $\rightarrow$ Emit Finding `[F-HDR-03]`.

### Module 4: Authentication Results Validator (`src/modules/auth_validator.py`)

* **Function Signature:** `def validate_authentication(evidence: EvidenceObject, msg: email.message.Message) -> EvidenceObject`
* **Algorithm:**
  1. Parse `Authentication-Results`, `Received-SPF`, and `DKIM-Signature` headers.
  2. Extract verdicts:
     * SPF: `pass`, `fail`, `softfail`, `neutral`, `none`.
     * DKIM: `pass`, `fail`, `none`.
     * DMARC: `pass`, `fail`, `none`.
  3. Check alignment between `From` domain and DKIM/SPF authorized domains.
  4. Emit Finding `[F-AUTH-01]` detailing the verdict with category `OBSERVED_EVIDENCE` and confidence `VERIFIED`.

### Module 5: Indicator & QR Extractor (`src/modules/indicator_extractor.py`)

* **Function Signature:** `def extract_indicators(evidence: EvidenceObject, msg: email.message.Message) -> EvidenceObject`
* **Algorithm:**
  1. Extract URLs from body text using regex: `https?://[^\s<>"]+|www\.[^\s<>"]+`.
  2. Extract URLs from HTML `href` and `src` attributes.
  3. Canonicalize domains and append to `evidence.indicators.urls` and `evidence.indicators.domains`.
  4. Iterate through attachments and inline MIME parts:
     * If MIME type is image (`image/png`, `image/jpeg`, `image/webp`):
       * Load image into `PIL.Image.open(io.BytesIO(part.get_payload(decode=True)))`.
       * Execute `pyzbar.decode(image)`.
       * For every decoded QR code, extract data string, append to `evidence.indicators.qr_payloads`, and emit Finding `[F-QR-01]` (`"QR Quishing payload detected: {url}"`, category `OBSERVED_EVIDENCE`).
     * If file is generic attachment, record filename, size, and SHA-256 hash.

### Module 6: Explainable Mathematical Risk Engine (`src/modules/risk_engine.py`)

* **Function Signature:** `def calculate_risk(evidence: EvidenceObject) -> EvidenceObject`
* **Mathematical Formula:**
  $$\text{Risk Score} = \sum_{i=1}^{8} (S_i \times W_i)$$
* **Component Weights ($W_i$):**
  * `nlp_phishing_keyword`: $0.25$ (Presence of urgent financial/credential phrases)
  * `header_anomaly`: $0.15$ (Display name mismatch = 0.8, Reply-To mismatch = 1.0)
  * `auth_failure`: $0.10$ (DMARC fail = 1.0, SPF fail = 0.7)
  * `url_reputation`: $0.15$ (IP-literal URL = 1.0, lookalike/punycode = 0.9, benign = 0.1)
  * `infra_risk`: $0.10$ (Known bulletproof/proxy subnet = 0.8, normal = 0.1)
  * `qr_quishing`: $0.10$ (QR payload present = 1.0, none = 0.0)
  * `campaign_similarity`: $0.10$ (Max similarity against seeded cluster)
  * `attachment_risk`: $0.05$ (Macro/executable = 1.0, inert = 0.0)
* **Score Bands:**
  * $\ge 0.85 \implies \text{CRITICAL}$
  * $\ge 0.65 \implies \text{HIGH}$
  * $\ge 0.35 \implies \text{MEDIUM}$
  * $< 0.35 \implies \text{LOW}$
* **Output:** Populate `evidence.risk.score`, `evidence.risk.band`, `evidence.risk.component_scores`, and detailed `rationale`.

### Module 7: Attack DNA & Campaign Similarity (`src/modules/attack_dna.py`)

* **Function Signature:** `def compute_attack_dna(evidence: EvidenceObject, seeded_db_path: str) -> EvidenceObject`
* **Algorithm:**
  1. Construct the 32-dimensional feature vector as defined in Section 10.
  2. Compute unit length $L_2$ normalization: $V_{\text{norm}} = \frac{V}{\|V\|_2}$.
  3. Load `seeded_campaigns.json`. Compute cosine similarity:
     $$\text{Cosine Similarity} = \frac{A \cdot B}{\|A\|_2 \|B\|_2}$$
  4. Return top matches with similarity $\ge 0.70$, detailing primary feature drivers (e.g. `"88% match with Campaign-Alpha driven by HTML structure and QR payload"`).

### Module 8: Citation-Constrained Attack Story (`src/modules/attack_story.py`)

* **Function Signature:** `def generate_grounded_story(evidence: EvidenceObject) -> EvidenceObject`
* **Algorithm:**
  1. Map existing `Finding` objects into a chronological narrative draft.
  2. **Strict Citation Validation Rule:**
     * Inspect every generated sentence using regex: `r"\[(F-[A-Z0-9\-]+)\]"`.
     * Extract cited finding IDs and verify they exist in `evidence.findings`.
     * **If a sentence does not cite at least one valid finding ID, discard it immediately.**
  3. Store validated sentences in `evidence.attack_story`.

### Module 9: Section 63 BSA Forensic Dossier Exporter (`src/modules/dossier_exporter.py`)

* **Function Signature:** `def export_evidence_package(evidence: EvidenceObject, output_dir: str) -> str`
* **Algorithm:**
  1. **Generate PDF (`CyberTrace_Forensic_Report.pdf`) via ReportLab:**
     * Header banner with Case ID, Timestamp, Risk Band, and Raw SHA-256 fingerprint.
     * Table of Custody Events.
     * Table of Header Relay Hops (from, by, IP, timestamp).
     * Authentication Summary (SPF, DKIM, DMARC).
     * Indicator Table (URLs, Domains, Decoded QR targets).
     * Citation-Enforced Incident Story.
     * **Section 63 Bharatiya Sakshya Adhiniyam (BSA) 2023 / Section 65B IEA Technical Certificate Block:** Pre-fills machine ID, operating system, software version, date/time range, hash digest, and signature block for the forensic investigator.
  2. **Package ZIP (`CT-{case_id}_evidence_package.zip`):**
     * `/raw/original_evidence.eml`
     * `/hashes/sha256_checksum.txt`
     * `/report/CyberTrace_Forensic_Report.pdf`
     * `/data/evidence_object.json`
     * `/data/iocs.csv`
  3. Return path to ZIP file.

---

## 12. FASTAPI REST API IMPLEMENTATION (`src/api/app.py`)

Expose these endpoints with full Pydantic validation:

* `POST /cases`: Ingests multipart file upload (`.eml`). Executes the full pipeline synchronously (or queued) and returns `EvidenceObject`.
* `GET /cases/{case_id}`: Returns stored `EvidenceObject` JSON.
* `POST /cases/{case_id}/verify`: Ingests re-uploaded `.eml` file. Calculates SHA-256 and compares it to `evidence.sha256`. Returns: `{ "case_id": case_id, "verified": true, "match": true, "original_hash": "...", "uploaded_hash": "..." }`.
* `GET /cases/{case_id}/report.pdf`: Returns PDF forensic report (`FileResponse`).
* `GET /cases/{case_id}/evidence.zip`: Returns complete Section 63 BSA evidence bundle ZIP (`FileResponse`).

---

## 13. AUTOMATED TEST SUITE & VERIFICATION HARNESS

Build comprehensive tests under `tests/` ensuring 100% pass rate:

1. **Synthetic EML Generator (`tests/fixtures/generate_synthetic_eml.py`):**
   * Script that outputs 3 test `.eml` files:
     * `clean_sample.eml`: Standard benign email, valid SPF/DKIM, no obfuscations.
     * `phishing_obfuscated.eml`: Spoofed From, Reply-To mismatch, `\u200B` zero-width spaces in subject, HTML `display:none` hidden text.
     * `quishing_sample.eml`: Contains an attached PNG generated using `qrcode` pointing to `https://fake-login.paypal-secure.cc/verify`.
2. **Unit Tests:**
   * `test_ingestion.py`: Asserts raw bytes match original file, SHA-256 is correct, custody event created.
   * `test_reconstruction.py`: Asserts zero-width characters stripped, HTML hidden DOM surfaced.
   * `test_headers_and_auth.py`: Asserts bottom-to-top hop ordering, flags Reply-To mismatch.
   * `test_qr_extractor.py`: Asserts pyzbar correctly decodes the synthetic QR attachment.
   * `test_risk_scoring.py`: Asserts risk score is between 0.0 and 1.0, high-risk sample triggers `CRITICAL` or `HIGH` band.
   * `test_attack_dna.py`: Asserts cosine similarity correctly identifies matched seeded campaign.
   * `test_story_citations.py`: Asserts sentences without `[F-xxx]` citations are discarded.
   * `test_verify_endpoint.py`: Asserts `/verify` returns `match: true` for identical file, `match: false` if a single byte changed.
3. **Adversarial Stress Test (`tests/test_adversarial_stress.py`):**
   * Applies 3 mutation types to `phishing_obfuscated.eml`:
     1. Whitespace padding injection.
     2. Cyrillic homoglyph swap on domain/subject.
     3. MIME part re-ordering.
   * Asserts CyberTrace de-obfuscates mutations and risk score varies by no more than $\pm 10\%$.

---

## 14. EXECUTION ORDER

1. Create directory structure and write `requirements.txt`.
2. Implement Pydantic data schemas in `src/models/evidence_object.py`.
3. Implement Modules 1 through 9 under `src/modules/`.
4. Implement `src/pipeline.py` and `src/api/app.py`.
5. Implement synthetic fixture generator and seed data in `tests/fixtures/`.
6. Implement all test files in `tests/`.
7. Execute `pytest -v` and verify all tests pass with 0 failures.
```
