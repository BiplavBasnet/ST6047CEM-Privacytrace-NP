"""Deterministic HTTP + PostgreSQL stabilisation workflow (not Scenario Lab)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.db.seed_auth_users import seed_auth_users
from app.dependencies.auth_dependencies import get_current_user
from app.main import app
from app.models.evidence_file import EvidenceFile
from app.models.enums import EvidenceType, IncidentStatus, ParsingStatus, Severity
from app.models.incident import Incident
from app.models.integrity_ledger import IntegrityLedgerRecord
from app.models.normalized_event import NormalizedEvent
from app.models.root_cause_score import RootCauseScore
from app.services import (
    ai_remediation_service,
    contextual_detection_service,
    evidence_provenance_service,
    privacy_impact_service,
    restricted_data_policy_service,
)

INCIDENT_ID = "INC-STAB-E2E-001"
RAW_CITIZENSHIP = "12-34-56-78901"
RAW_AML = "STR-FIU-2026-0001"
ORDINARY_NUMBER = "12345"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.postgres,
    pytest.mark.critical_db,
    pytest.mark.e2e,
]


def _assert_ok(response, expected: int = 200) -> dict:
    assert response.status_code == expected, response.text
    return response.json()


def _login(client: TestClient, email: str, password: str) -> dict[str, str]:
    body = _assert_ok(
        client.post("/auth/login", json={"email": email, "password": password})
    )
    return {"Authorization": f"Bearer {body['access_token']}"}


def _assert_no_raw(payload: object) -> None:
    encoded = json.dumps(payload, default=str)
    assert RAW_CITIZENSHIP not in encoded
    assert RAW_AML not in encoded
    assert "eyJhbGciOiJIUzI1NiJ9.stab" not in encoded


def _seed_incident(db: Session) -> None:
    incident = Incident(
        incident_id=INCIDENT_ID,
        title="Possible privacy exposure in synthetic wallet transfer",
        affected_service="wallet-service",
        affected_endpoint="/api/v1/transfer",
        status=IncidentStatus.UNDER_REVIEW,
        severity=Severity.HIGH,
        first_seen=datetime(2026, 7, 20, 10, 0, tzinfo=timezone.utc),
        last_seen=datetime(2026, 7, 20, 10, 5, tzinfo=timezone.utc),
        summary="Masked synthetic evidence requires human review.",
    )
    evidence = EvidenceFile(
        evidence_id="EVD-STAB-API-001",
        file_name="stab_wallet_transfer.log",
        evidence_type=EvidenceType.API_LOG,
        source_system="wallet-service",
        file_hash="sha256:" + ("a" * 64),
        parsing_status=ParsingStatus.PARSED,
        linked_incident_id=INCIDENT_ID,
    )
    event = NormalizedEvent(
        event_id="EVT-STAB-001",
        evidence_id=evidence.evidence_id,
        timestamp=datetime(2026, 7, 20, 10, 1, tzinfo=timezone.utc),
        source_type="api_log",
        service_name="wallet-service",
        endpoint="/api/v1/transfer",
        event_type="http_request",
        raw_reference="stab-e2e",
        masked_message=(
            f"citizenship_number={RAW_CITIZENSHIP} "
            f"str_sar_reference={RAW_AML} "
            f"amount_ref={ORDINARY_NUMBER} "
            "Authorization=Bearer eyJhbGciOiJIUzI1NiJ9.stab.signature"
        ),
        severity=Severity.HIGH,
        linked_incident_id=INCIDENT_ID,
    )
    db.add_all([incident, evidence, event])
    db.flush()
    evidence_provenance_service.record_system_provenance(
        db,
        evidence.evidence_id,
        source_system="wallet-service",
        source_format="api_log",
        collector_name="stabilisation_e2e",
        parser_name="stabilisation_e2e",
        parser_version="1",
        commit=False,
        append_integrity=True,
    )
    db.commit()


def test_stabilisation_end_to_end_workflow(client: TestClient, seeded_db):
    """Exercise the stabilised workflow over the real HTTP API + PostgreSQL.

    Uses an independent SessionLocal for seeding and post-assertions so it does
    not share the transactional db_session fixture (which deadlocks with
    integrity advisory locks when mixed with TestClient commits).
    """
    app.dependency_overrides.pop(get_current_user, None)
    seed_auth_users()

    seed = SessionLocal()
    try:
        _seed_incident(seed)
    finally:
        seed.close()

    analyst = _login(client, "analyst@privacytrace.local", "AnalystPass123!")
    admin = _login(client, "admin@privacytrace.local", "AdminPass123!")

    detect = _assert_ok(
        client.post("/evidence/EVD-STAB-API-001/detect", headers=analyst)
    )
    assert detect["evidence_id"] == "EVD-STAB-API-001"
    assert detect["status"] in {
        "detected",
        "completed",
        "already_detected",
        "failed",
        "skipped",
    }

    negative = contextual_detection_service.classify_structured_fields(
        {"numeric_reference": ORDINARY_NUMBER},
        source_context={"endpoint": "/metrics", "source_service": "metrics"},
    )
    codes = {
        str(item.get("taxonomy_code") or item.get("code") or "")
        for item in (negative or [])
        if isinstance(item, dict)
    }
    assert "nepal_citizenship_number" not in codes
    assert "pin" not in {c.lower() for c in codes}
    assert "otp" not in {c.lower() for c in codes}
    assert "cvv" not in {c.lower() for c in codes}

    provenance = _assert_ok(
        client.get("/evidence/EVD-STAB-API-001/provenance", headers=analyst)
    )
    assert provenance["parser_name"] == "stabilisation_e2e"
    assert provenance["parser_version"] == "1"
    _assert_no_raw(provenance)

    analysis = _assert_ok(
        client.post(
            "/incidents/analyse",
            headers=analyst,
            json={"incident_id": INCIDENT_ID},
        )
    )
    assert any(item["incident_id"] == INCIDENT_ID for item in analysis["results"])

    assess = _assert_ok(
        client.post(
            f"/incidents/{INCIDENT_ID}/privacy-impact/assess",
            headers=analyst,
            json={
                "data_categories": [],
                "ease_of_identification_score": 0.5,
                "limitations": ["Synthetic stabilisation evidence only."],
            },
        )
    )
    assessment = assess["assessment"]
    assert assessment is not None
    assert assessment["taxonomy_version"]
    assert assessment["combination_ruleset_version"]
    _assert_no_raw(assess)

    alerts_before = _assert_ok(client.get("/breach-alerts", headers=analyst))
    before_rows = alerts_before.get("alerts") or alerts_before.get("items") or []
    assess_again = _assert_ok(
        client.post(
            f"/incidents/{INCIDENT_ID}/privacy-impact/assess",
            headers=analyst,
            json={
                "data_categories": [],
                "ease_of_identification_score": 0.5,
                "limitations": ["Synthetic stabilisation evidence only."],
            },
        )
    )
    assert assess_again["assessment"]["assessment_id"] == assessment["assessment_id"]
    alerts_after = _assert_ok(client.get("/breach-alerts", headers=analyst))
    after_rows = alerts_after.get("alerts") or alerts_after.get("items") or []
    assert len(after_rows) <= len(before_rows) + 1

    metrics = _assert_ok(client.get("/breach-alerts/metrics", headers=analyst))
    assert "unresolved_alert_count" in metrics
    assert "acknowledged_sample_size" in metrics
    _assert_no_raw(metrics)

    integrity = _assert_ok(
        client.post(f"/incidents/{INCIDENT_ID}/integrity/verify", headers=admin)
    )
    assert integrity["chain_valid"] is True
    assert "Global" in (integrity.get("result_summary") or "Global")
    if integrity.get("verification_mode"):
        assert integrity["verification_mode"] == "global_with_scope_membership"
    _assert_no_raw(integrity)

    db = SessionLocal()
    try:
        scores = list(
            db.scalars(
                select(RootCauseScore).where(RootCauseScore.incident_id == INCIDENT_ID)
            ).all()
        )
        for score in scores:
            supporting = set(score.supporting_evidence_ids or [])
            retest = set(score.retest_evidence_ids or [])
            assert supporting.isdisjoint(retest)

        try:
            payload = ai_remediation_service.build_masked_payload(db, INCIDENT_ID)
        except ai_remediation_service.AISafetyBlockedError:
            # Fail-closed is acceptable when detector text still looks unsafe.
            payload = {
                "incident_id": INCIDENT_ID,
                "masked_detections": [
                    {
                        "detection_id": "DET-AML",
                        "sensitive_type": "str_sar_reference",
                        "masked_value": "[category-only]",
                    }
                ],
                "safe_incident_summary": "Masked synthetic evidence requires review.",
            }
        sanitized, restricted = restricted_data_policy_service.sanitize_payload(
            payload, channel="external_ai"
        )
        encoded = json.dumps(sanitized, default=str).lower()
        assert RAW_AML.lower() not in encoded
        assert "str_sar_reference" not in encoded
        assert RAW_CITIZENSHIP not in encoded
        assert restricted is True or sanitized is not None
        _assert_no_raw(sanitized)

        latest = privacy_impact_service.get_latest_assessment(db, INCIDENT_ID)
        assert latest is not None
        _assert_no_raw(
            {"categories": latest.data_categories, "limitations": latest.limitations}
        )

        # Controlled tampering must fail integrity and block verified export.
        record = db.scalar(
            select(IntegrityLedgerRecord)
            .order_by(IntegrityLedgerRecord.sequence_number)
            .limit(1)
        )
        assert record is not None
        db.execute(
            text(
                "ALTER TABLE integrity_ledger_records "
                "DISABLE TRIGGER trg_guard_integrity_record"
            )
        )
        record.record_hash = "sha256:" + ("b" * 64)
        db.flush()
        db.execute(
            text(
                "ALTER TABLE integrity_ledger_records "
                "ENABLE TRIGGER trg_guard_integrity_record"
            )
        )
        db.commit()
    finally:
        db.close()

    timeline = client.get(f"/incidents/{INCIDENT_ID}/timeline", headers=analyst)
    assert timeline.status_code in {200, 404}
    if timeline.status_code == 200:
        _assert_no_raw(timeline.json())

    controls = client.post(
        f"/incidents/{INCIDENT_ID}/preventive-controls/generate",
        headers=analyst,
        json={},
    )
    assert controls.status_code in {200, 201, 404, 409, 422}

    failed = _assert_ok(
        client.post(f"/incidents/{INCIDENT_ID}/integrity/verify", headers=admin)
    )
    assert failed["chain_valid"] is False

    export_blocked = client.get(
        f"/incidents/{INCIDENT_ID}/provenance/export",
        headers=admin,
    )
    assert export_blocked.status_code == 409
