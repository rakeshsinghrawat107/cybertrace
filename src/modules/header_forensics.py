"""Module 3: Header Forensics & Received Hop Reconstruction."""

import email
import ipaddress
import re
from email.utils import parseaddr
from typing import Any, Dict, List, Optional, Tuple

from src.models.evidence_object import (
    ConfidenceLevel,
    EvidenceObject,
    Finding,
    FindingCategory,
)

WELL_KNOWN_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix",
    "chase", "bank of america", "wells fargo", "sbi", "hdfc", "icici",
    "docu sign", "docusign", "dropbox", "meta", "facebook", "instagram",
]

RECEIVED_IP_REGEX = re.compile(
    r"\[?((?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+)\]?"
)


def _is_private_or_loopback(ip_str: str) -> bool:
    """Checks whether an IP address belongs to RFC 1918, RFC 6598 (CGNAT), or loopback."""
    try:
        ip = ipaddress.ip_address(ip_str.strip("[]"))
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except ValueError:
        return False


def _extract_domain(addr: str) -> str:
    """Extracts lowercase domain name from an email address."""
    if "@" in addr:
        return addr.split("@")[-1].strip().lower()
    return ""


def parse_received_hop(header_val: str, hop_index: int) -> Dict[str, Any]:
    """Parses a single RFC 5321 Received header line."""
    hop_data: Dict[str, Any] = {
        "hop": hop_index,
        "raw": header_val.replace("\r", " ").replace("\n", " ").strip(),
        "from_host": None,
        "by_host": None,
        "ip": None,
        "is_private": False,
        "protocol": None,
        "timestamp": None,
    }
    
    # Extract 'from'
    from_match = re.search(r"\bfrom\s+([^\s;]+)", header_val, re.I)
    if from_match:
        hop_data["from_host"] = from_match.group(1).strip()
        
    # Extract 'by'
    by_match = re.search(r"\bby\s+([^\s;]+)", header_val, re.I)
    if by_match:
        hop_data["by_host"] = by_match.group(1).strip()
        
    # Extract 'with'
    with_match = re.search(r"\bwith\s+([^\s;]+)", header_val, re.I)
    if with_match:
        hop_data["protocol"] = with_match.group(1).strip()
        
    # Extract timestamp (after semicolon)
    if ";" in header_val:
        hop_data["timestamp"] = header_val.split(";")[-1].strip()
        
    # Extract IP address
    ip_matches = RECEIVED_IP_REGEX.findall(header_val)
    for candidate in ip_matches:
        try:
            ip = ipaddress.ip_address(candidate)
            hop_data["ip"] = str(ip)
            hop_data["is_private"] = _is_private_or_loopback(str(ip))
            break
        except ValueError:
            continue
            
    return hop_data


def analyze_headers(evidence: EvidenceObject, msg: email.message.Message) -> EvidenceObject:
    """Reconstructs bottom-to-top chronological relay hops and identifies header-level adversarial anomalies."""
    # 1. Parse Received hops in reverse (bottom-to-top chronological order)
    received_headers = msg.get_all("Received", [])
    reversed_hops = list(reversed(received_headers))
    
    parsed_hops = []
    for idx, raw_h in enumerate(reversed_hops, start=1):
        parsed = parse_received_hop(raw_h, idx)
        parsed_hops.append(parsed)
        if parsed.get("ip") and not parsed.get("is_private"):
            if parsed["ip"] not in evidence.indicators.ips:
                evidence.indicators.ips.append(parsed["ip"])
                
    # 2. Check From vs Reply-To mismatch
    from_header = msg.get("From", "")
    reply_to_header = msg.get("Reply-To", "")
    return_path_header = msg.get("Return-Path", "")
    
    from_realname, from_email = parseaddr(from_header)
    reply_realname, reply_email = parseaddr(reply_to_header)
    _, return_path_email = parseaddr(return_path_header)
    
    from_domain = _extract_domain(from_email)
    reply_domain = _extract_domain(reply_email)
    return_path_domain = _extract_domain(return_path_email)
    
    if reply_domain and from_domain and (reply_domain != from_domain):
        evidence.findings.append(
            Finding(
                id="F-HDR-01",
                module="header_forensics",
                category=FindingCategory.OBSERVED_EVIDENCE,
                claim=f"Reply-To domain mismatch: 'From' points to '{from_domain}', but 'Reply-To' redirects responses to '{reply_domain}'.",
                evidence_refs=["HDR-REPLYTO"],
                confidence=ConfidenceLevel.VERIFIED,
            )
        )
        
    # 3. Check Brand Impersonation in Display Name
    lower_realname = from_realname.lower()
    for brand in WELL_KNOWN_BRANDS:
        if brand in lower_realname:
            # Check if domain actually matches brand
            if brand.replace(" ", "") not in from_domain:
                evidence.findings.append(
                    Finding(
                        id="F-HDR-02",
                        module="header_forensics",
                        category=FindingCategory.INFERENCE,
                        claim=f"Display Name Impersonation: Name claims identity '{from_realname}' (Brand: {brand.upper()}), but originating domain is '{from_domain}'.",
                        evidence_refs=["HDR-FROM"],
                        confidence=ConfidenceLevel.HIGH,
                    )
                )
                break
                
    # 4. Check Missing or Malformed Message-ID
    msg_id = msg.get("Message-ID", "")
    if not msg_id or not re.match(r"^<[^@]+@[^>]+>$", msg_id.strip()):
        evidence.findings.append(
            Finding(
                id="F-HDR-03",
                module="header_forensics",
                category=FindingCategory.OBSERVED_EVIDENCE,
                claim="Missing or non-RFC compliant Message-ID header (characteristic of mass-mailing tools).",
                evidence_refs=["HDR-MSGID"],
                confidence=ConfidenceLevel.VERIFIED,
            )
        )
        
    # Store parsed hops in headers dictionary for downstream reporting
    if not isinstance(evidence.email.headers, dict):
        evidence.email.headers = {}
    evidence.email.headers["_parsed_received_hops"] = parsed_hops
    evidence.email.headers["_from_email"] = from_email
    evidence.email.headers["_reply_to_email"] = reply_email
    evidence.email.headers["_return_path_email"] = return_path_email
    
    return evidence
