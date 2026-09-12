"""Module 2: Adversarial Email Reconstruction & De-Obfuscation."""

import email
import re
import unicodedata
from email import policy
from typing import List, Tuple
from bs4 import BeautifulSoup

from src.models.evidence_object import (
    ConfidenceLevel,
    EvidenceObject,
    Finding,
    FindingCategory,
)

# Zero-width Unicode characters and invisible format controls
ZERO_WIDTH_CHARS = {
    "\u200B": "ZERO_WIDTH_SPACE",
    "\u200C": "ZERO_WIDTH_NON_JOINER",
    "\u200D": "ZERO_WIDTH_JOINER",
    "\uFEFF": "ZERO_WIDTH_NO_BREAK_SPACE",
    "\u2060": "WORD_JOINER",
    "\u200E": "LEFT_TO_RIGHT_MARK",
    "\u200F": "RIGHT_TO_LEFT_MARK",
}

CSS_HIDDEN_PATTERN = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(px|pt|em|rem)?|color\s*:\s*transparent|opacity\s*:\s*0)",
    re.IGNORECASE,
)


def _strip_zero_width(text: str) -> Tuple[str, List[str], int]:
    """Strips zero-width characters and returns cleaned text, removed logs, and total count."""
    removed_logs = []
    total_count = 0
    cleaned_chars = []
    
    for char in text:
        if char in ZERO_WIDTH_CHARS or (unicodedata.category(char) == "Cf" and char not in ("\n", "\r", "\t")):
            name = ZERO_WIDTH_CHARS.get(char, f"U+{ord(char):04X}")
            removed_logs.append(f"Zero-width character stripped: {name} (U+{ord(char):04X})")
            total_count += 1
        else:
            cleaned_chars.append(char)
            
    return "".join(cleaned_chars), removed_logs, total_count


def _extract_hidden_dom_elements(html_content: str) -> Tuple[str, List[str]]:
    """Inspects CSS DOM hiding tactics (display:none, font-size:0, matching colors)."""
    hidden_texts = []
    try:
        soup = BeautifulSoup(html_content, "lxml")
    except Exception:
        soup = BeautifulSoup(html_content, "html.parser")
        
    for tag in soup.find_all(True):
        style = tag.get("style", "")
        if CSS_HIDDEN_PATTERN.search(style):
            text = tag.get_text(strip=True)
            if text:
                hidden_texts.append(f"CSS Hidden DOM: '{text}' (style: {style})")
            tag.decompose()
            continue
            
        # Check background-color matching text color
        color_match = re.search(r"color\s*:\s*(#[0-9a-fA-F]{3,6}|white|rgb\([^)]+\))", style, re.I)
        bg_match = re.search(r"background(-color)?\s*:\s*(#[0-9a-fA-F]{3,6}|white|rgb\([^)]+\))", style, re.I)
        if color_match and bg_match:
            c = color_match.group(1).lower().strip()
            bg = bg_match.group(2).lower().strip()
            if c == bg or (c in ("#fff", "#ffffff", "white") and bg in ("#fff", "#ffffff", "white")):
                text = tag.get_text(strip=True)
                if text:
                    hidden_texts.append(f"Color-camouflage Hidden Text: '{text}'")
                tag.decompose()
                
    cleaned_html = soup.get_text(separator="\n", strip=True)
    return cleaned_html, hidden_texts


def reconstruct_email(evidence: EvidenceObject, raw_bytes: bytes) -> EvidenceObject:
    """Parses MIME structure, normalizes homoglyphs, strips zero-width characters, and extracts cloaked CSS elements."""
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    
    # Extract headers
    headers_dict = {}
    for k, v in msg.items():
        headers_dict[k] = str(v)
    evidence.email.headers = headers_dict
    
    plain_parts = []
    html_parts = []
    
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get("Content-Disposition", ""))
            if "attachment" in cdisp.lower():
                continue
            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
                if ctype == "text/plain":
                    plain_parts.append(text)
                elif ctype == "text/html":
                    html_parts.append(text)
            except Exception:
                continue
    else:
        ctype = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
            if ctype == "text/html":
                html_parts.append(text)
            else:
                plain_parts.append(text)
                
    raw_plain = "\n".join(plain_parts)
    raw_html = "\n".join(html_parts)
    
    evidence.email.body_raw = raw_plain or raw_html
    
    # Check multipart mismatch (plain text benign/empty, but HTML contains active links/content)
    if raw_plain and raw_html:
        url_regex = re.compile(r"https?://\S+")
        plain_urls = url_regex.findall(raw_plain)
        html_urls = url_regex.findall(raw_html)
        if len(plain_urls) == 0 and len(html_urls) > 0:
            evidence.email.multipart_mismatch = True
            evidence.findings.append(
                Finding(
                    id="F-MIME",
                    module="reconstruction",
                    category=FindingCategory.OBSERVED_EVIDENCE,
                    claim=f"Multipart text/html mismatch detected: Plain text has 0 links while HTML contains {len(html_urls)} links (SEG desynchronization tactic).",
                    evidence_refs=["MIME-001"],
                    confidence=ConfidenceLevel.VERIFIED,
                )
            )
            
    # Process Subject and Body for zero-width characters
    subject_raw = headers_dict.get("Subject", "")
    cleaned_subject, zw_subj_logs, zw_subj_count = _strip_zero_width(subject_raw)
    if zw_subj_count > 0:
        headers_dict["Subject"] = cleaned_subject
        
    target_text = raw_plain if raw_plain else raw_html
    cleaned_text, zw_logs, zw_count = _strip_zero_width(target_text)
    zw_logs = zw_subj_logs + zw_logs
    zw_count += zw_subj_count
    
    # CSS hidden inspection
    hidden_dom_logs = []
    if raw_html:
        cleaned_html_text, hidden_dom_logs = _extract_hidden_dom_elements(raw_html)
        if not raw_plain:
            cleaned_text, zw_logs2, zw_count2 = _strip_zero_width(cleaned_html_text)
            zw_logs.extend(zw_logs2)
            zw_count += zw_count2
            
    # Homoglyph NFKC normalization
    normalized_body = unicodedata.normalize("NFKC", cleaned_text)
    
    evidence.email.body_normalized = normalized_body
    evidence.email.hidden_content_removed = zw_logs + hidden_dom_logs
    
    # Findings emission
    if zw_count > 0:
        evidence.findings.append(
            Finding(
                id="F-OBFUSCATION",
                module="reconstruction",
                category=FindingCategory.OBSERVED_EVIDENCE,
                claim=f"Detected {zw_count} zero-width / invisible formatting characters used for NLP parser evasion.",
                evidence_refs=["ZW-001"],
                confidence=ConfidenceLevel.VERIFIED,
            )
        )
        
    if len(hidden_dom_logs) > 0:
        evidence.findings.append(
            Finding(
                id="F-HIDDEN-DOM",
                module="reconstruction",
                category=FindingCategory.OBSERVED_EVIDENCE,
                claim=f"Detected {len(hidden_dom_logs)} CSS cloaked / hidden DOM elements (display:none or zero font-size).",
                evidence_refs=["DOM-001"],
                confidence=ConfidenceLevel.VERIFIED,
            )
        )
        
    return evidence
