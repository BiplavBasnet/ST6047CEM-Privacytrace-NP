"""Phase 11.7 NIST documentation and security profile tests."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import get_backend_root

DOCS = get_backend_root().parent / "docs"


def test_nist_security_profile_doc_exists():
    assert (DOCS / "NIST_SECURITY_PROFILE.md").is_file()


def test_nist_csf_functions_mentioned():
    text = (DOCS / "NIST_SECURITY_PROFILE.md").read_text(encoding="utf-8")
    for fn in ("Govern", "Identify", "Protect", "Detect", "Respond", "Recover"):
        assert fn in text


def test_sp_800_53_mapping_exists():
    text = (DOCS / "NIST_SECURITY_PROFILE.md").read_text(encoding="utf-8")
    assert "800-53" in text
    assert "AC" in text and "AU" in text


def test_sp_800_63b_mapping_exists():
    text = (DOCS / "NIST_SECURITY_PROFILE.md").read_text(encoding="utf-8")
    assert "800-63B" in text or "800-63b" in text.lower()


def test_sp_800_57_mapping_exists():
    assert "800-57" in (DOCS / "NIST_SECURITY_PROFILE.md").read_text(encoding="utf-8")


def test_sp_800_38d_mapping_exists():
    assert "800-38D" in (DOCS / "NIST_SECURITY_PROFILE.md").read_text(encoding="utf-8")


def test_sp_800_56_asymmetric_mapping_exists():
    text = (DOCS / "NIST_SECURITY_PROFILE.md").read_text(encoding="utf-8")
    assert "800-56" in text


def test_sp_800_90a_mapping_exists():
    assert "800-90A" in (DOCS / "NIST_SECURITY_PROFILE.md").read_text(encoding="utf-8")


def test_sp_800_61_mapping_exists():
    assert "800-61" in (DOCS / "NIST_SECURITY_PROFILE.md").read_text(encoding="utf-8")


def test_security_limitations_not_fips_certified():
    text = (DOCS / "SECURITY_LIMITATIONS.md").read_text(encoding="utf-8").lower()
    assert "not" in text and ("fips-certified" in text or "fips certified" in text)


def test_docs_do_not_claim_formal_certification():
    limitations = (DOCS / "SECURITY_LIMITATIONS.md").read_text(encoding="utf-8").lower()
    assert "not" in limitations and "fips" in limitations
    profile = (DOCS / "NIST_SECURITY_PROFILE.md").read_text(encoding="utf-8").lower()
    assert "not formal" in profile or "not formal certification" in profile


def test_security_self_check_endpoint_exists(client: TestClient, seeded_db):
    r = client.get("/security/self-check")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
