"""Tests for FastAPI REST API & Section 63 BSA /verify Proof Endpoint."""

import io
import zipfile


def test_api_case_lifecycle_and_verification(client, clean_eml_bytes):
    # 1. Ingest case
    response = client.post(
        "/cases",
        files={"file": ("clean_sample.eml", io.BytesIO(clean_eml_bytes), "message/rfc822")}
    )
    assert response.status_code == 201
    case_data = response.json()
    case_id = case_data["case_id"]
    original_sha256 = case_data["evidence"]["sha256"]
    
    # 2. Retrieve case
    get_res = client.get(f"/cases/{case_id}")
    assert get_res.status_code == 200
    assert get_res.json()["case_id"] == case_id
    
    # 3. Verify exact file match (Zero Hash Drift)
    verify_res = client.post(
        f"/cases/{case_id}/verify",
        files={"file": ("clean_sample.eml", io.BytesIO(clean_eml_bytes), "message/rfc822")}
    )
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["verified"] is True
    assert v_data["match"] is True
    assert v_data["status"] == "CRYPTOGRAPHIC_MATCH"
    assert v_data["legal_admissibility"] == "VALID_SECTION_63_BSA"
    
    # 4. Verify altered byte causes hash drift rejection
    tampered_bytes = clean_eml_bytes + b"\nTAMPERED_BYTE"
    tamper_res = client.post(
        f"/cases/{case_id}/verify",
        files={"file": ("tampered.eml", io.BytesIO(tampered_bytes), "message/rfc822")}
    )
    assert tamper_res.status_code == 200
    t_data = tamper_res.json()
    assert t_data["match"] is False
    assert t_data["status"] == "HASH_DRIFT_DETECTED"
    assert t_data["legal_admissibility"] == "INVALID_TAMPERED"
    
    # 5. Download Forensic Report PDF
    pdf_res = client.get(f"/cases/{case_id}/report.pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 1000
    
    # 6. Download Evidence Package ZIP
    zip_res = client.get(f"/cases/{case_id}/evidence.zip")
    assert zip_res.status_code == 200
    assert zip_res.headers["content-type"] == "application/zip"
    
    with zipfile.ZipFile(io.BytesIO(zip_res.content), "r") as zf:
        namelist = zf.namelist()
        assert "raw/original_evidence.eml" in namelist
        assert "hashes/sha256_checksum.txt" in namelist
        assert "report/CyberTrace_Forensic_Report.pdf" in namelist
        assert "data/evidence_object.json" in namelist
        assert "data/iocs.csv" in namelist


def test_dashboard_and_demo_endpoints(client):
    # Test root dashboard serves HTML
    home_res = client.get("/")
    assert home_res.status_code == 200
    assert "text/html" in home_res.headers["content-type"]
    assert "CYBERTRACE" in home_res.text
    
    # Test quick demo scenarios
    clean_demo = client.post("/cases/demo/clean")
    assert clean_demo.status_code == 200
    assert clean_demo.json()["risk"]["band"] == "LOW"
    
    phish_demo = client.post("/cases/demo/phishing")
    assert phish_demo.status_code == 200
    assert phish_demo.json()["risk"]["score"] >= 0.65
    
    quish_demo = client.post("/cases/demo/quishing")
    assert quish_demo.status_code == 200
    assert len(quish_demo.json()["indicators"]["qr_payloads"]) >= 1
