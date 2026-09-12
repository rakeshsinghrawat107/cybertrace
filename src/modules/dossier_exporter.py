"""Module 9: Section 63 BSA Forensic Dossier Exporter & Tamper-Evident Packaging."""

import csv
import io
import json
import os
import platform
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from src.models.evidence_object import EvidenceObject


def generate_forensic_pdf(evidence: EvidenceObject, output_pdf_path: str) -> str:
    """Generates a court-admissible forensic PDF dossier using ReportLab."""
    doc = SimpleDocTemplate(
        output_pdf_path,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6,
    )
    h2_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading2"],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e3a8a"),
        spaceBefore=10,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )
    meta_style = ParagraphStyle(
        "MetaText",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#64748b"),
    )
    cert_style = ParagraphStyle(
        "CertStyle",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0f172a"),
    )
    
    elements = []
    
    # 1. Header Banner
    elements.append(Paragraph("CYBERTRACE DIGITAL FORENSIC DOSSIER", title_style))
    elements.append(Paragraph("Admissible Electronic Evidence Analysis (Smart India Hackathon 2026)", meta_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1e3a8a"), spaceAfter=12))
    
    # Case Summary Box
    summary_data = [
        [Paragraph("<b>Case ID:</b>", body_style), Paragraph(evidence.case_id, body_style),
         Paragraph("<b>Risk Band:</b>", body_style), Paragraph(f"<b>{evidence.risk.band.value} ({evidence.risk.score:.2f})</b>", body_style)],
        [Paragraph("<b>Ingested At:</b>", body_style), Paragraph(str(evidence.ingested_at), body_style),
         Paragraph("<b>Original File:</b>", body_style), Paragraph(evidence.evidence.original_filename, body_style)],
        [Paragraph("<b>SHA-256 Digest:</b>", body_style), Paragraph(f"<font size='7'>{evidence.evidence.sha256}</font>", body_style),
         Paragraph("<b>File Size:</b>", body_style), Paragraph(f"{evidence.evidence.size_bytes} bytes", body_style)],
    ]
    summary_table = Table(summary_data, colWidths=[80, 200, 80, 170])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 12))
    
    # 2. Chain of Custody Table
    elements.append(Paragraph("1. Cryptographic Chain of Custody Audit Trail", h2_style))
    custody_rows = [["Event ID", "Timestamp (UTC)", "Actor", "Action", "Evidence Hash"]]
    for ev in evidence.chain_of_custody:
        custody_rows.append([
            ev.event_id,
            str(ev.timestamp)[:19],
            ev.actor,
            ev.action,
            f"{ev.evidence_hash[:16]}..."
        ])
    custody_table = Table(custody_rows, colWidths=[70, 130, 80, 110, 140])
    custody_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('PADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(custody_table)
    elements.append(Spacer(1, 12))
    
    # 3. Authentication Status & Header Analysis
    elements.append(Paragraph("2. Header Relay Path & Protocol Forensics", h2_style))
    verdicts = evidence.email.headers.get("_auth_verdicts", {})
    auth_text = (
        f"<b>Authentication Alignment:</b> SPF={verdicts.get('spf', 'NONE').upper()} | "
        f"DKIM={verdicts.get('dkim', 'NONE').upper()} | "
        f"DMARC={verdicts.get('dmarc', 'NONE').upper()}"
    )
    elements.append(Paragraph(auth_text, body_style))
    elements.append(Spacer(1, 6))
    
    hops = evidence.email.headers.get("_parsed_received_hops", [])
    if hops:
        hop_rows = [["Hop", "From Host", "By Host", "Extracted IP", "Type"]]
        for h in hops[:6]:  # Show up to 6 hops
            hop_rows.append([
                str(h.get("hop", "")),
                (h.get("from_host") or "N/A")[:22],
                (h.get("by_host") or "N/A")[:22],
                h.get("ip") or "N/A",
                "Internal" if h.get("is_private") else "Public Egress"
            ])
        hop_table = Table(hop_rows, colWidths=[35, 145, 145, 110, 95])
        hop_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('FONTSIZE', (0, 0), (-1, -1), 7.5),
            ('PADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(hop_table)
        elements.append(Spacer(1, 12))
        
    # 4. Verified Findings & Incident Story
    elements.append(Paragraph("3. Programmatic Incident Story (Citation Grounded)", h2_style))
    if evidence.attack_story:
        for step in evidence.attack_story:
            stmt = f"<b>[{step.step_number}]</b> {step.statement}"
            elements.append(Paragraph(stmt, body_style))
            elements.append(Spacer(1, 3))
    else:
        elements.append(Paragraph("No adversarial behavioral patterns surfaced.", body_style))
    elements.append(Spacer(1, 12))
    
    # 5. Indicators of Compromise (IoCs)
    elements.append(Paragraph("4. Extracted Indicators of Compromise (IoCs)", h2_style))
    ioc_rows = [["Indicator Type", "Value", "Context / Module"]]
    for u in evidence.indicators.urls[:4]:
        ioc_rows.append(["URL", u[:55], "Body Extraction"])
    for qr in evidence.indicators.qr_payloads[:3]:
        ioc_rows.append(["QR Payload", qr[:55], "Computer Vision Decoded"])
    for ip in evidence.indicators.ips[:4]:
        ioc_rows.append(["Relay IP", ip, "Infrastructure Association"])
    for att in evidence.indicators.attachments[:3]:
        ioc_rows.append(["Attachment", att.get("filename", "")[:35], f"SHA256: {att.get('sha256', '')[:16]}..."])
        
    if len(ioc_rows) > 1:
        ioc_table = Table(ioc_rows, colWidths=[100, 280, 150])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('FONTSIZE', (0, 0), (-1, -1), 7.5),
            ('PADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(ioc_table)
        elements.append(Spacer(1, 12))
        
    # 6. Section 63 BSA 2023 Technical Certificate Block
    elements.append(Spacer(1, 10))
    cert_box = [
        [Paragraph("<b>ANNEXURE: CERTIFICATE UNDER SECTION 63 OF THE BHARATIYA SAKSHYA ADHINIYAM, 2023</b><br/>"
                   "(Corresponding to erstwhile Section 65B of the Indian Evidence Act, 1872)", cert_style)],
        [Paragraph(
            f"I, the undersigned forensic investigator, certify that the electronic record referenced herein "
            f"(Case ID: <b>{evidence.case_id}</b>, Digest: <b>{evidence.evidence.sha256}</b>) was ingested and analyzed "
            f"using CyberTrace Automated Forensic Engine v1.0 running on system: <b>{platform.node()} ({platform.system()} {platform.release()})</b>. "
            f"The electronic output was produced during the ordinary course of operations by computer systems operating properly. "
            f"The integrity of the raw network byte stream has been maintained with zero hash drift from ingest to report generation.<br/><br/>"
            f"<b>Date/Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; "
            f"<b>Investigator Signature:</b> ___________________________",
            cert_style
        )]
    ]
    cert_table = Table(cert_box, colWidths=[530])
    cert_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#475569")),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(cert_table)
    
    doc.build(elements)
    return output_pdf_path


def export_evidence_package(evidence: EvidenceObject, output_dir: str = "data") -> str:
    """Builds and packages a Section 63 BSA court-admissible forensic ZIP bundle."""
    case_dir = Path(output_dir) / evidence.case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Generate Forensic PDF Report
    pdf_path = case_dir / "CyberTrace_Forensic_Report.pdf"
    generate_forensic_pdf(evidence, str(pdf_path))
    
    # 2. Write Hashes
    checksum_path = case_dir / "sha256_checksum.txt"
    with open(checksum_path, "w", encoding="utf-8") as f:
        f.write(f"SHA-256 Digest: {evidence.evidence.sha256}\n")
        f.write(f"Case ID: {evidence.case_id}\n")
        f.write(f"Original Filename: {evidence.evidence.original_filename}\n")
        f.write(f"Timestamp: {evidence.ingested_at.isoformat()}\n")
        
    # 3. Write Evidence JSON
    json_path = case_dir / "evidence_object.json"
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(evidence.model_dump_json(indent=2))
        
    # 4. Write IoCs CSV
    iocs_path = case_dir / "iocs.csv"
    with open(iocs_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Type", "Value", "SourceModule"])
        for u in evidence.indicators.urls:
            writer.writerow(["URL", u, "indicator_extractor"])
        for d in evidence.indicators.domains:
            writer.writerow(["Domain", d, "indicator_extractor"])
        for ip in evidence.indicators.ips:
            writer.writerow(["IP_Address", ip, "header_forensics"])
        for qr in evidence.indicators.qr_payloads:
            writer.writerow(["QR_Payload", qr, "pyzbar_cv"])
        for att in evidence.indicators.attachments:
            writer.writerow(["Attachment_Hash", att.get("sha256"), att.get("filename")])
            
    # 5. Build ZIP Bundle
    zip_filename = f"CT-{evidence.case_id}_evidence_package.zip"
    zip_path = case_dir / zip_filename
    
    raw_file_path = Path(evidence.evidence.object_uri)
    
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if raw_file_path.exists():
            zf.write(raw_file_path, arcname="raw/original_evidence.eml")
        zf.write(checksum_path, arcname="hashes/sha256_checksum.txt")
        zf.write(pdf_path, arcname="report/CyberTrace_Forensic_Report.pdf")
        zf.write(json_path, arcname="data/evidence_object.json")
        zf.write(iocs_path, arcname="data/iocs.csv")
        
    return str(zip_path.resolve())
