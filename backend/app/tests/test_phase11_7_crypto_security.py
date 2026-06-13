"""Phase 11.7 cryptographic security tests."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
import jwt
from sqlalchemy import select

from app.config import get_backend_root
from app.models.audit_log import AuditLog
from app.models.enums import EvidenceType, UserRole
from app.models.report import Report
from app.models.user import User
from app.services import (
    audit_service,
    auth_service,
    crypto_service,
    field_encryption_service,
    file_encryption_service,
    key_management_service,
    password_service,
)
from app.tests.auth_test_utils import seed_demo_users_in_db
from app.tests.crypto_test_utils import write_demo_key_set

SEED_INCIDENT = "INC-SEED-001"


def test_aes_gcm_roundtrip():
    dek = crypto_service.generate_dek()
    nonce = crypto_service.generate_nonce()
    pt = b"privacytrace-secret-payload"
    aad = b"test|rec|field"
    ct = crypto_service.encrypt_aes_gcm(plaintext=pt, dek=dek, nonce=nonce, associated_data=aad)
    out = crypto_service.decrypt_aes_gcm(ciphertext=ct, dek=dek, nonce=nonce, associated_data=aad)
    assert out == pt


def test_aes_gcm_tampering_detected():
    dek = crypto_service.generate_dek()
    nonce = crypto_service.generate_nonce()
    ct = crypto_service.encrypt_aes_gcm(
        plaintext=b"x", dek=dek, nonce=nonce, associated_data=b"aad"
    )
    tampered = bytearray(ct)
    tampered[-1] ^= 0xFF
    with pytest.raises(crypto_service.TamperDetectedError):
        crypto_service.decrypt_aes_gcm(
            ciphertext=bytes(tampered), dek=dek, nonce=nonce, associated_data=b"aad"
        )


def test_unique_nonce_per_encryption(phase11_7_crypto_keys):
    nonces = set()
    for i in range(5):
        payload = field_encryption_service.encrypt_json(
            value={"n": i},
            table="t",
            record_id=str(i),
            field="f",
        )
        nonces.add(payload["nonce"])
    assert len(nonces) == 5


def test_rsa_oaep_wrap_unwrap(phase11_7_crypto_keys):
    private_key = key_management_service.load_data_wrap_private_key()
    public_key = key_management_service.load_data_wrap_public_key()
    dek = crypto_service.generate_dek()
    wrapped = crypto_service.wrap_dek_rsa_oaep(dek=dek, public_key=public_key)
    unwrapped = crypto_service.unwrap_dek_rsa_oaep(wrapped_dek=wrapped, private_key=private_key)
    assert unwrapped == dek


def test_wrong_private_key_cannot_unwrap(phase11_7_crypto_keys, tmp_path):
    other_dir = tmp_path / "other"
    write_demo_key_set(other_dir)
    wrong_private = crypto_service.load_rsa_private_key(str(other_dir / "data_wrap_private.pem"))
    public_key = key_management_service.load_data_wrap_public_key()
    wrapped = crypto_service.wrap_dek_rsa_oaep(dek=crypto_service.generate_dek(), public_key=public_key)
    with pytest.raises(crypto_service.CryptoError):
        crypto_service.unwrap_dek_rsa_oaep(wrapped_dek=wrapped, private_key=wrong_private)


def test_encrypted_payload_has_no_plaintext_secret(phase11_7_crypto_keys):
    secret = "super-secret-token-value"
    payload = field_encryption_service.encrypt_json(
        value={"token": secret},
        table="reports",
        record_id="R1",
        field="content",
    )
    blob = json.dumps(payload)
    assert secret not in blob


def test_evidence_encrypted_at_rest(db_session, phase11_7_crypto_keys):
    from app.services import ingestion_service

    content = b"timestamp,message\n2024-01-01,masked event\n"
    record = ingestion_service.ingest_file(
        db_session,
        content=content,
        file_name="ev.log",
        evidence_type=EvidenceType.API_LOG,
    )
    db_session.commit()
    assert record.is_encrypted is True
    assert record.encrypted_file_path
    path = get_backend_root() / record.encrypted_file_path
    assert path.is_file()
    on_disk = path.read_text(encoding="utf-8")
    assert "masked event" not in on_disk


def test_report_encrypted_at_rest(db_session, seeded_db, phase11_7_crypto_keys):
    from app.services import report_service

    report_service.generate_report(db_session, SEED_INCIDENT, report_type="json")
    db_session.commit()
    row = db_session.scalar(
        select(Report).where(Report.incident_id == SEED_INCIDENT).order_by(Report.id.desc())
    )
    assert row is not None
    assert row.is_encrypted is True
    assert row.content_encrypted is not None
    assert row.content_json is None


def test_audit_details_encrypted_at_rest(db_session, phase11_7_crypto_keys):
    audit_service.log_action(
        db_session,
        action="test_crypto_audit",
        target_type="incident",
        target_id=SEED_INCIDENT,
        details={"note": "operational detail"},
        actor_id=None,
    )
    db_session.commit()
    row = db_session.scalar(select(AuditLog).order_by(AuditLog.id.desc()))
    assert row is not None
    assert row.is_encrypted is True
    assert row.details_encrypted is not None


def test_llm_output_encrypted_when_persisted(db_session, seeded_db, phase11_7_crypto_keys):
    from app.models.llm_report import LlmReport
    from app.services import llm_investigation_service

    llm_investigation_service._persist_report(
        db_session,
        incident_id=SEED_INCIDENT,
        provider_used="template",
        model_name=None,
        context_hash="sha256:abc",
        output_json={"incident_summary": "demo"},
        safety_status="ok",
        validation_errors=None,
    )
    row = db_session.scalar(select(LlmReport).order_by(LlmReport.id.desc()))
    assert row is not None
    assert row.is_encrypted is True
    assert row.output_encrypted is not None


def test_api_decrypts_report_after_auth(client: TestClient, seeded_db, phase11_7_crypto_keys):
    # Report generation now asserts the integrity ledger is verifiable before
    # export. The seed helper creates evidence directly (bypassing the audit
    # trail), so establish a real ledger head first, matching how a normally
    # operated incident would already have at least one recorded event.
    from app.database import SessionLocal

    seed_db = SessionLocal()
    try:
        audit_service.log_action(
            seed_db,
            action="test_seed_audit_trail",
            actor_id=None,
            target_type="incident",
            target_id=SEED_INCIDENT,
            details={"incident_id": SEED_INCIDENT, "note": "seed audit trail for integrity chain"},
        )
        seed_db.commit()
    finally:
        seed_db.close()

    r = client.post(
        f"/reports/incidents/{SEED_INCIDENT}/generate",
        json={"report_type": "json"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "content" in body
    assert SEED_INCIDENT in r.text


def test_unauthorised_cannot_access_security_key_status(client, seeded_db):
    from app.dependencies.auth_dependencies import get_current_user
    from app.main import app

    app.dependency_overrides.pop(get_current_user, None)
    try:
        r = client.get("/security/key-status")
        assert r.status_code == 401
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_security_profile_no_private_keys(client: TestClient, seeded_db, phase11_7_crypto_keys):
    r = client.get("/security/profile")
    assert r.status_code == 200
    text = r.text.lower()
    assert "begin private key" not in text
    assert "jwt_private" not in text


def test_security_self_check_safe(client: TestClient, seeded_db, phase11_7_crypto_keys):
    r = client.get("/security/self-check")
    data = r.json()
    assert data["private_keys_not_exposed_by_api"] is True
    assert "private" not in json.dumps(data).lower() or "private_keys_not_exposed" in r.text


def test_jwt_uses_asymmetric_signing(db_session, phase11_7_crypto_keys):
    users = seed_demo_users_in_db(db_session)
    admin = users["admin"]["user"]
    token = auth_service.create_access_token(user=admin)
    header = jwt.get_unverified_header(token)
    assert header.get("alg") == "RS256"
    assert header.get("kid")


def test_invalid_jwt_rejected(db_session, phase11_7_crypto_keys):
    with pytest.raises(auth_service.InvalidTokenError):
        auth_service.decode_access_token("not.a.valid.jwt")


def test_password_hash_pbkdf2():
    h = password_service.hash_password("TestPass123!")
    assert h.startswith("$pbkdf2-sha256$")
    assert password_service.verify_password("TestPass123!", h)


def test_plaintext_password_not_stored(db_session):
    users = seed_demo_users_in_db(db_session)
    u = users["admin"]["user"]
    assert u.password_hash != "AdminPass123!"


def test_password_hash_not_in_user_api(client: TestClient, seeded_db):
    r = client.get("/users")
    assert r.status_code == 200
    assert "password_hash" not in r.text


def test_metadata_no_raw_sensitive(phase11_7_crypto_keys):
    payload = field_encryption_service.encrypt_json(
        value={"email": "user@example.com"},
        table="audit_logs",
        record_id="1",
        field="details",
    )
    assert "user@example.com" not in json.dumps(payload)


def test_gitignore_blocks_private_keys():
    gi = (get_backend_root().parent / ".gitignore").read_text(encoding="utf-8")
    assert "backend/keys/" in gi
    assert "*.pem" in gi


def test_key_generation_script_exists():
    assert (get_backend_root().parent / "scripts" / "generate_demo_keys.ps1").is_file()


def test_key_rotation_script_exists():
    assert (get_backend_root().parent / "scripts" / "rotate_demo_keys.ps1").is_file()
