# CyberTrace — Ready-to-Go Production Architecture Package

This repository contains the complete architectural foundation, formal specifications, dependency manifests, execution runbooks, and autonomous build prompts created by a Principal Software Architect before implementing **CyberTrace** for Smart India Hackathon 2026 (Problem Statement: AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform).

---

## 1. Repository Contents & Architecture Artifacts

| File | Description | Purpose / Audience |
|---|---|---|
| [`requirements.txt`](./requirements.txt) | Pinned Python 3.11+ production and testing dependencies with security and memory justifications. | DevOps & Developers |
| [`EXECUTION_ORDER_AND_BUILD_RUNBOOK.md`](./EXECUTION_ORDER_AND_BUILD_RUNBOOK.md) | Phased implementation sequence (Phases 0–8), quality invariants, gate criteria, and verification commands. | Lead Architect & Engineers |
| [`ARCHITECTURE_DECISION_RECORDS_ADR.md`](./ARCHITECTURE_DECISION_RECORDS_ADR.md) | Formal engineering justifications for 8 architectural choices (Preservation Before Parsing, QR CV, Section 63 BSA, etc.). | Judges, Faculty, Security Auditors |
| [`MASTER_READY_TO_GO_BUILD_PROMPT.md`](./MASTER_READY_TO_GO_BUILD_PROMPT.md) | Self-contained, autonomous master prompt to feed into an AI coding agent to generate the complete codebase with 100% test coverage. | AI Agents / Developers |

---

## 2. The 6 Core Innovations Encapsulated in this Package

1. **Preservation Before Parsing (Zero Hash Drift):**  
   Streaming unparsed network bytes to storage and locking the SHA-256 digest *before* any MIME parser touches the file, provable via a live `/verify` endpoint.
2. **Adversarial MIME & DOM De-Obfuscation:**  
   Multi-pass stripping of zero-width Unicode characters (`U+200B`), NFKC homoglyph normalization, and BeautifulSoup CSS DOM hiding extraction (`display:none`, `font-size:0`).
3. **Native Multimodal QR Quishing Extraction:**  
   In-memory computer vision scanning via `pyzbar` and `Pillow` on all attached/inline images without writing untrusted files to disk.
4. **Zero-Hallucination Programmatic AI Guardrails:**  
   Generative AI models receive only structured finding tokens (`[F-001]`). Programmatic regex AST validator rejects any statement lacking verified citations.
5. **Multi-Signal "Attack DNA" Vector Clustering:**  
   32-dimensional normalized structural feature vector ($L_2$ unit length) matched against historical campaigns using PostgreSQL `pgvector`'s cosine distance (`<=>`).
6. **Built-in Section 63 BSA 2023 Digital Evidence Packaging:**  
   One-click generation of a court-ready evidence ZIP bundle: untouched `.eml`, SHA-256 checksum, custody audit log, IoC CSV, and an audit-ready PDF with a pre-filled Section 63 BSA technical certificate.

---

## 3. Quickstart: Building the Software

To initiate software construction using these assets:

1. **Review the Execution Order:**  
   Read [`EXECUTION_ORDER_AND_BUILD_RUNBOOK.md`](./EXECUTION_ORDER_AND_BUILD_RUNBOOK.md) to understand the phased dependencies and invariants.
2. **Setup the Virtual Environment:**  
   Install dependencies from [`requirements.txt`](./requirements.txt).
3. **Trigger Code Generation:**  
   Feed [`MASTER_READY_TO_GO_BUILD_PROMPT.md`](./MASTER_READY_TO_GO_BUILD_PROMPT.md) to the coding agent to generate the `src/` modules, `tests/`, and synthetic fixtures.
4. **Execute Verification:**  
   Run `pytest -v` to ensure 100% test pass rate across all modules and adversarial stress tests.

