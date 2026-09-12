"""Module 5: Indicator & QR Extractor (Multimodal Quishing Computer Vision)."""

import email
import hashlib
import io
import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from PIL import Image

import os
import sys
from pathlib import Path

# Ensure Windows DLL search path includes pyzbar package directory
if hasattr(os, "add_dll_directory"):
    try:
        pyzbar_dir = Path(sys.prefix) / "Lib" / "site-packages" / "pyzbar"
        if pyzbar_dir.exists():
            os.add_dll_directory(str(pyzbar_dir))
    except Exception:
        pass

try:
    from pyzbar import pyzbar
    PYZBAR_AVAILABLE = True
except Exception:
    PYZBAR_AVAILABLE = False

try:
    import cv2
    import numpy as np
    OPENCV_AVAILABLE = True
except Exception:
    OPENCV_AVAILABLE = False

from src.models.evidence_object import (
    ConfidenceLevel,
    EvidenceObject,
    Finding,
    FindingCategory,
)

URL_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'{}|\\^`]+",
    re.IGNORECASE
)


def _clean_url(url: str) -> str:
    """Strips trailing punctuation that might get attached in body text."""
    url = url.strip()
    while url and url[-1] in ('.', ',', ';', ':', ')', ']', '}', '>', '"', "'"):
        url = url[:-1]
    if url.lower().startswith("www."):
        url = "http://" + url
    return url


def _extract_domain(url: str) -> str:
    """Extracts lowercase domain name from URL."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0].strip().lower()
        return domain
    except Exception:
        return ""


def extract_indicators(evidence: EvidenceObject, msg: email.message.Message) -> EvidenceObject:
    """Extracts URLs, domains, attachments, and decodes QR codes from attached or inline images in memory."""
    found_urls: Set[str] = set()
    found_domains: Set[str] = set()
    found_qr_payloads: List[str] = []
    attachment_list: List[Dict[str, Any]] = []
    
    # 1. Extract URLs from plain and normalized body (or directly from message parts)
    body_to_search = f"{evidence.email.body_raw}\n{evidence.email.body_normalized}"
    if not body_to_search.strip():
        # Fallback if reconstruction was not run prior to indicator extraction
        for p in msg.walk():
            if p.get_content_type() == "text/plain":
                payload_b = p.get_payload(decode=True)
                if payload_b:
                    charset = p.get_content_charset() or "utf-8"
                    body_to_search += "\n" + payload_b.decode(charset, errors="replace")
                    
    for u in URL_REGEX.findall(body_to_search):
        cleaned = _clean_url(u)
        if cleaned:
            found_urls.add(cleaned)
            dom = _extract_domain(cleaned)
            if dom:
                found_domains.add(dom)
                
    # 2. Iterate MIME parts for HTML href/src and attachments
    for part in msg.walk():
        ctype = part.get_content_type().lower()
        cdisp = str(part.get("Content-Disposition", "")).lower()
        filename = part.get_filename() or ""
        
        # HTML links
        if ctype == "text/html":
            payload = part.get_payload(decode=True)
            if payload:
                try:
                    soup = BeautifulSoup(payload, "html.parser")
                    for a_tag in soup.find_all(["a", "link"]):
                        href = a_tag.get("href")
                        if href and isinstance(href, str) and (href.startswith("http") or href.startswith("www")):
                            cleaned = _clean_url(href)
                            found_urls.add(cleaned)
                            dom = _extract_domain(cleaned)
                            if dom:
                                found_domains.add(dom)
                except Exception:
                    pass
                    
        # Attachment or Image part
        is_image = ctype.startswith("image/")
        is_attachment = "attachment" in cdisp or bool(filename)
        
        if is_image or is_attachment:
            payload = part.get_payload(decode=True)
            if payload:
                part_sha256 = hashlib.sha256(payload).hexdigest()
                part_size = len(payload)
                
                # Check for QR code in images using dual-engine CV
                if is_image:
                    qr_decoded_texts = []
                    try:
                        img = Image.open(io.BytesIO(payload)).convert("RGB")
                        
                        # Engine 1: pyzbar
                        if PYZBAR_AVAILABLE:
                            try:
                                decoded_codes = pyzbar.decode(img)
                                for qr in decoded_codes:
                                    t = qr.data.decode("utf-8", errors="replace").strip()
                                    if t and t not in qr_decoded_texts:
                                        qr_decoded_texts.append(t)
                            except Exception:
                                pass
                                
                        # Engine 2: OpenCV QRCodeDetector fallback
                        if not qr_decoded_texts and OPENCV_AVAILABLE:
                            try:
                                open_cv_image = np.array(img)
                                detector = cv2.QRCodeDetector()
                                val, pts, _ = detector.detectAndDecode(open_cv_image)
                                if val and val.strip() and val.strip() not in qr_decoded_texts:
                                    qr_decoded_texts.append(val.strip())
                            except Exception:
                                pass
                                
                        for qr_text in qr_decoded_texts:
                            found_qr_payloads.append(qr_text)
                            evidence.findings.append(
                                Finding(
                                    id="F-QR-01",
                                    module="indicator_extractor",
                                    category=FindingCategory.OBSERVED_EVIDENCE,
                                    claim=f"QR Quishing payload detected in image '{filename or 'inline'}': {qr_text}",
                                    evidence_refs=["QR-001"],
                                    confidence=ConfidenceLevel.VERIFIED,
                                )
                            )
                            if qr_text.startswith("http://") or qr_text.startswith("https://"):
                                cleaned = _clean_url(qr_text)
                                found_urls.add(cleaned)
                                dom = _extract_domain(cleaned)
                                if dom:
                                    found_domains.add(dom)
                    except Exception:
                        pass
                        
                # Record attachment metadata
                if is_attachment:
                    attachment_list.append({
                        "filename": filename or f"unnamed_{part_sha256[:8]}",
                        "content_type": ctype,
                        "size_bytes": part_size,
                        "sha256": part_sha256,
                    })
                    
    # Update EvidenceObject indicators
    for u in sorted(found_urls):
        if u not in evidence.indicators.urls:
            evidence.indicators.urls.append(u)
            
    for d in sorted(found_domains):
        if d not in evidence.indicators.domains:
            evidence.indicators.domains.append(d)
            
    for qr_val in found_qr_payloads:
        if qr_val not in evidence.indicators.qr_payloads:
            evidence.indicators.qr_payloads.append(qr_val)
            
    evidence.indicators.attachments = attachment_list
    
    return evidence
