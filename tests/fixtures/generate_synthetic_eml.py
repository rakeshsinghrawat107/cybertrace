"""Synthetic Test Email Generator for CyberTrace Verification Harness."""

import email
import io
from email.message import EmailMessage
from pathlib import Path
import qrcode


def create_clean_eml() -> bytes:
    """Generates a benign corporate notification email with valid headers and authentication."""
    msg = EmailMessage()
    msg["From"] = "Internal IT Support <support@acme-corp.com>"
    msg["To"] = "employee@acme-corp.com"
    msg["Subject"] = "Quarterly IT Infrastructure Maintenance Schedule"
    msg["Date"] = "Wed, 10 Sep 2026 14:00:00 +0000"
    msg["Message-ID"] = "<20260910140000.12345.it@acme-corp.com>"
    msg["Received"] = (
        "from mail-relay.acme-corp.com ([198.51.100.25]) by mx.acme-corp.com with ESMTPS id abc12345; "
        "Wed, 10 Sep 2026 14:00:01 +0000"
    )
    msg["Authentication-Results"] = (
        "mx.acme-corp.com; dkim=pass header.i=@acme-corp.com; spf=pass smtp.mailfrom=support@acme-corp.com; dmarc=pass"
    )
    msg.set_content(
        "Hello Team,\n\n"
        "Please be advised that the internal portal will undergo scheduled maintenance this Saturday.\n"
        "No action is required from your side.\n\n"
        "Best regards,\nIT Infrastructure Operations\nhttps://portal.acme-corp.com/status"
    )
    return msg.as_bytes()


def create_phishing_obfuscated_eml() -> bytes:
    """Generates an adversarial phishing email with zero-width characters, CSS hidden DOM, and Reply-To mismatch."""
    msg = EmailMessage()
    msg["From"] = '"PayPal Security Team" <service-update@secure-billing-gateway.xyz>'
    msg["Reply-To"] = "attacker-exfil@evil-drop.cc"
    msg["To"] = "victim@target-corp.com"
    # Inject zero-width space U+200B inside "Urgent" and "Account"
    msg["Subject"] = "U\u200Br\u200Bg\u200Be\u200Bn\u200Bt: Acc\u200Bount Suspended - Immediate Verification Required"
    msg["Date"] = "Thu, 11 Sep 2026 09:15:00 +0000"
    # Malformed or missing Message-ID
    msg["Message-ID"] = "invalid-no-brackets"
    msg["Received"] = (
        "from evil-vps.bulletproof-host.ru ([203.0.113.88]) by mx.target-corp.com with ESMTP id zyx987; "
        "Thu, 11 Sep 2026 09:15:01 +0000"
    )
    msg["Authentication-Results"] = (
        "mx.target-corp.com; spf=fail smtp.mailfrom=service-update@secure-billing-gateway.xyz; "
        "dkim=fail; dmarc=fail action=none"
    )
    
    plain_content = (
        "Dear Customer,\n\n"
        "Your account has been suspended due to suspicious unauthorized access.\n"
        "Please verify your credentials immediately to avoid permanent account termination.\n\n"
        "Immediate Action Required: Wire transfer or update your payment details at "
        "http://203.0.113.88/secure-login\n"
    )
    
    html_content = (
        "<html><body>"
        "<p>Dear Customer,</p>"
        "<p>Your account has been suspended due to unauthorized login attempts.</p>"
        "<div style='display:none; font-size:0px;'>BENIGN CRAWLER TEXT: All systems normal 2026 weather report</div>"
        "<p style='color:#ffffff; background-color:#ffffff;'>INVISIBLE DOM CLOAKING TEXT</p>"
        "<p><a href='http://203.0.113.88/secure-login'>Click here immediately to verify your account</a></p>"
        "</body></html>"
    )
    
    msg.set_content(plain_content)
    msg.add_alternative(html_content, subtype="html")
    return msg.as_bytes()


def create_quishing_eml() -> bytes:
    """Generates an image-only Quishing email with an embedded QR code pointing to a malicious credential harvester."""
    msg = EmailMessage()
    msg["From"] = '"Microsoft 365 Security" <authenticator@ms-cloud-security.cc>'
    msg["To"] = "executive@enterprise.org"
    msg["Subject"] = "Action Required: Re-authenticate Microsoft MFA Authenticator Token"
    msg["Date"] = "Fri, 12 Sep 2026 08:30:00 +0000"
    msg["Message-ID"] = "<20260912083000.mfa@ms-cloud-security.cc>"
    msg["Received"] = (
        "from relay.ms-cloud-security.cc ([198.51.100.99]) by mx.enterprise.org with ESMTP; "
        "Fri, 12 Sep 2026 08:30:02 +0000"
    )
    msg["Authentication-Results"] = (
        "mx.enterprise.org; spf=neutral; dkim=none; dmarc=none"
    )
    
    msg.set_content(
        "Dear User,\n\n"
        "Your multi-factor authentication token has expired. Scan the attached QR code below using your "
        "mobile camera to complete two-factor authentication and unlock your corporate inbox.\n\n"
        "Best regards,\nCorporate Cloud Security"
    )
    
    # Generate in-memory QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data("https://fake-login.paypal-secure.cc/verify")
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format="PNG")
    qr_bytes = img_byte_arr.getvalue()
    
    msg.add_attachment(
        qr_bytes,
        maintype="image",
        subtype="png",
        filename="Security_MFA_QRCode.png"
    )
    return msg.as_bytes()


def generate_all_fixtures(target_dir: str = "tests/fixtures") -> None:
    """Writes all 3 synthetic EML files to the target fixture directory."""
    out_dir = Path(target_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    clean_eml = create_clean_eml()
    with open(out_dir / "clean_sample.eml", "wb") as f:
        f.write(clean_eml)
        
    phish_eml = create_phishing_obfuscated_eml()
    with open(out_dir / "phishing_obfuscated.eml", "wb") as f:
        f.write(phish_eml)
        
    quish_eml = create_quishing_eml()
    with open(out_dir / "quishing_sample.eml", "wb") as f:
        f.write(quish_eml)
        
    print(f"Generated 3 synthetic .eml fixtures in '{out_dir}'")


if __name__ == "__main__":
    generate_all_fixtures()
