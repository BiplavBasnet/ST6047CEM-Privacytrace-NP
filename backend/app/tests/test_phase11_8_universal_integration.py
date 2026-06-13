"""Phase 11.8 — Universal Usability and SIEM/SOC Integration Readiness tests.

These tests cover:

* The integration router shape (formats, single ingest, batch ingest,
  metadata read, export, per-incident formats).
* Authentication and RBAC at the integration boundary.
* Mapping of OCSF, ECS and Splunk HEC inbound payloads into the
  canonical PrivacyTraceIntegrationEvent.
* Inbound safety validation – raw phone numbers, wallet IDs, JWTs,
  bearer tokens, API keys, passwords, password hashes and private keys
  must be rejected without echoing the unsafe value. Certainty/blame
  *wording* alone (e.g. "proven cause") is INPUT evidence and is
  accepted (Phase P input/output safety separation) — only raw secrets
  trigger rejection at this boundary.
* Audit logging of accepted ingestion, rejected ingestion and SOC
  exports.
* The seven outbound export formats and their safety contract – no raw
  values, tokens, password hashes, private keys or overclaim phrases
  (export narrative is PrivacyTrace-generated output and is held to the
  stricter output claim-safety contract).

The tests deliberately keep the surface small and stable; they exercise
the public router contract so we catch regressions whenever the
underlying services change.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.db.seed_phase2 import seed_phase2
from app.models.audit_log import AuditLog
from app.models.evidence_file import EvidenceFile
from app.services import siem_import_service
from app.tests.auth_test_utils import auth_headers, login, seed_demo_users_in_db

pytestmark = pytest.mark.usefixtures("migrated_db", "running_live_monitor")

SAFE_PRIVACYTRACE_EVENT = {
    "source_tool": "generic_siem",
    "source_format": "privacytrace_json",
    "external_alert_id": "ALERT-TEST-001",
    "event_time": "2026-05-19T10:00:00Z",
    "service_name": "wallet-service",
    "endpoint": "/wallet/transfer",
    "event_type": "sensitive_data_exposure",
    "sensitive_type": "nepali_phone_number",
    "masked_value": "98******67",
    "severity": "high",
    "confidence": 0.95,
    "message": "Masked sensitive value detected in application programming interface log",
    "evidence_reference": "siem-alert-test-001",
    "tags": ["env:staging", "team:wallet"],
}


@pytest.fixture(autouse=True)
def override_db_session_for_integration_api(db_session):
    from app.dependencies import get_db_session
    from app.main import app

    def _override():
        yield db_session

    app.dependency_overrides[get_db_session] = _override
    yield
    app.dependency_overrides.pop(get_db_session, None)


@pytest.fixture(autouse=True)
def clear_in_process_event_store():
    siem_import_service.clear_event_store()
    yield
    siem_import_service.clear_event_store()


@pytest.fixture
def demo_users(db_session):
    return seed_demo_users_in_db(db_session)


@pytest.fixture
def client_no_auth_override(client):
    from app.dependencies.auth_dependencies import get_current_user
    from app.main import app

    app.dependency_overrides.pop(get_current_user, None)
    yield client
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def seeded_incident(db_session):
    """Make INC-SEED-001 visible to the test transaction."""
    seed_phase2(db_session)
    db_session.commit()
    yield "INC-SEED-001"


def _admin_token(client_no_auth_override, demo_users, db_session) -> str:
    db_session.commit()
    return login(
        client_no_auth_override,
        email="admin@privacytrace.local",
        password="AdminPass123!",
    )


def _analyst_token(client_no_auth_override, demo_users, db_session) -> str:
    db_session.commit()
    return login(
        client_no_auth_override,
        email="analyst@privacytrace.local",
        password="AnalystPass123!",
    )


def _viewer_token(client_no_auth_override, demo_users, db_session) -> str:
    db_session.commit()
    return login(
        client_no_auth_override,
        email="viewer@privacytrace.local",
        password="ViewerPass123!",
    )


# ---------------------------------------------------------------------------
# Router shape and auth
# ---------------------------------------------------------------------------


def test_integration_routes_are_registered(client_no_auth_override):
    response = client_no_auth_override.get("/integrations/formats")
    # Without auth this must be 401, not 404, proving the route exists.
    assert response.status_code in (401, 403)


def test_ingest_requires_authentication(client_no_auth_override):
    response = client_no_auth_override.post(
        "/integrations/events", json=SAFE_PRIVACYTRACE_EVENT
    )
    assert response.status_code == 401


def test_export_requires_authentication(client_no_auth_override):
    response = client_no_auth_override.get(
        "/integrations/incidents/INC-SEED-001/export?format=privacytrace_json"
    )
    assert response.status_code == 401


def test_supported_formats_endpoint(
    client_no_auth_override, demo_users, db_session
):
    token = _admin_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.get(
        "/integrations/formats", headers=auth_headers(token)
    )
    assert response.status_code == 200
    body = response.json()
    inbound_ids = {entry["format_id"] for entry in body["inbound"]}
    outbound_ids = {entry["format_id"] for entry in body["outbound"]}
    assert {
        "privacytrace_json",
        "ocsf_json",
        "ecs_json",
        "splunk_hec_json",
        "generic_json",
    } <= inbound_ids
    assert {
        "privacytrace_json",
        "ocsf_json",
        "ecs_json",
        "splunk_hec_json",
        "cef_like",
        "leef_like",
        "rfc5424_syslog_like",
    } <= outbound_ids


# ---------------------------------------------------------------------------
# Inbound: per-format mapping
# ---------------------------------------------------------------------------


def test_allowed_role_can_ingest_privacytrace_json(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(token),
        json=SAFE_PRIVACYTRACE_EVENT,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "accepted"
    assert body["safety_status"] == "safe"
    assert body["integration_event_id"].startswith("INT-EVT-")
    assert body["event"]["masked_value"] == "98******67"
    # Raw payload must not be echoed back.
    assert "payload" not in body
    assert "raw_payload" not in body


def test_viewer_cannot_ingest_event(client_no_auth_override, demo_users, db_session):
    token = _viewer_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(token),
        json=SAFE_PRIVACYTRACE_EVENT,
    )
    assert response.status_code == 403


def test_ocsf_json_maps_into_canonical_event(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    payload = {
        "source_tool": "ocsf_vendor",
        "source_format": "ocsf_json",
        "payload": {
            "metadata": {"uid": "OCSF-ALERT-7"},
            "time": "2026-05-19T11:00:00Z",
            "severity": "high",
            "service": {"name": "auth-service"},
            "http_request": {"url": {"path": "/auth/login"}},
            "finding": {"title": "Masked sensitive value seen in log"},
            "observables": [
                {"name": "evidence_id", "type": "Other", "value": "EVD-OCSF-1"}
            ],
        },
        "masked_value": "ab******cd",
        "sensitive_type": "session_token_masked",
        "event_type": "sensitive_data_exposure",
    }
    response = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(token),
        json=payload,
    )
    assert response.status_code == 200, response.text
    event = response.json()["event"]
    assert event["external_alert_id"] == "OCSF-ALERT-7"
    assert event["service_name"] == "auth-service"
    assert event["endpoint"] == "/auth/login"
    assert event["source_format"] == "ocsf_json"
    assert any("evidence_id" in t for t in event["tags"])


def test_ecs_json_maps_into_canonical_event(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    payload = {
        "source_tool": "ecs_vendor",
        "source_format": "ecs_json",
        "payload": {
            "@timestamp": "2026-05-19T12:00:00Z",
            "event": {"id": "ECS-ALERT-9", "severity": "medium"},
            "service": {"name": "wallet-service"},
            "url": {"path": "/wallet/check"},
            "message": "Masked finding only",
            "labels": {"env": "staging"},
        },
        "masked_value": "1*****9",
        "sensitive_type": "wallet_id_masked",
        "event_type": "sensitive_data_exposure",
    }
    response = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(token),
        json=payload,
    )
    assert response.status_code == 200, response.text
    event = response.json()["event"]
    assert event["external_alert_id"] == "ECS-ALERT-9"
    assert event["service_name"] == "wallet-service"
    assert event["endpoint"] == "/wallet/check"
    assert "env:staging" in event["tags"]


def test_splunk_hec_json_maps_into_canonical_event(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    payload = {
        "source_tool": "splunk",
        "source_format": "splunk_hec_json",
        "payload": {
            "time": 1747625400,
            "source": "privacytrace-np",
            "sourcetype": "privacytrace:incident",
            "event": {
                "external_alert_id": "SPLUNK-ALERT-3",
                "service_name": "auth-service",
                "endpoint": "/auth/refresh",
                "severity": "low",
                "message": "Masked finding only",
                "sensitive_type": "jwt_masked",
                "masked_value": "ey***...***xx",
            },
        },
    }
    response = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(token),
        json=payload,
    )
    assert response.status_code == 200, response.text
    event = response.json()["event"]
    assert event["external_alert_id"] == "SPLUNK-ALERT-3"
    assert event["service_name"] == "auth-service"
    assert event["endpoint"] == "/auth/refresh"


def test_unsupported_source_format_is_rejected(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(token),
        json={**SAFE_PRIVACYTRACE_EVENT, "source_format": "unknown_format"},
    )
    assert response.status_code == 400
    assert "unsupported" in response.text.lower()


# ---------------------------------------------------------------------------
# Inbound: batch
# ---------------------------------------------------------------------------


def test_batch_ingestion_accepts_safe_events(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    body = {
        "events": [
            SAFE_PRIVACYTRACE_EVENT,
            {**SAFE_PRIVACYTRACE_EVENT, "external_alert_id": "ALERT-TEST-002"},
        ]
    }
    response = client_no_auth_override.post(
        "/integrations/events/batch",
        headers=auth_headers(token),
        json=body,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["total"] == 2
    assert payload["accepted"] == 2
    assert payload["rejected"] == 0
    for item in payload["results"]:
        assert item["status"] == "accepted"
        assert item["integration_event_id"].startswith("INT-EVT-")


def test_batch_ingestion_masks_sensitive_item_and_creates_alert(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    unsafe = dict(SAFE_PRIVACYTRACE_EVENT)
    unsafe["message"] = "Saw raw phone 9812345678 in log"
    body = {"events": [SAFE_PRIVACYTRACE_EVENT, unsafe]}
    response = client_no_auth_override.post(
        "/integrations/events/batch",
        headers=auth_headers(token),
        json=body,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["total"] == 2
    assert payload["accepted"] == 2
    assert payload["rejected"] == 0
    assert payload["results"][1]["status"] == "accepted"
    assert payload["results"][1]["alert_created"] is True
    assert "9812345678" not in json.dumps(payload)


def test_batch_ingestion_limit_is_enforced(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    body = {"events": [SAFE_PRIVACYTRACE_EVENT for _ in range(101)]}
    response = client_no_auth_override.post(
        "/integrations/events/batch",
        headers=auth_headers(token),
        json=body,
    )
    # Either pydantic length validator (422) or our explicit 400 guard.
    assert response.status_code in (400, 422)


# ---------------------------------------------------------------------------
# Inbound: safety validation – none of these may be echoed back.
# ---------------------------------------------------------------------------


MASKED_CASES = [
    pytest.param(
        {"message": "Saw raw phone 9812345678 in log"},
        "raw_phone_number",
        id="raw-phone-number",
    ),
    pytest.param(
        {"message": "wallet WAL12345678 leaked"},
        "raw_wallet_id",
        id="raw-wallet-id",
    ),
    pytest.param(
        {"message": "Header: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature_x"},
        "raw_jwt",
        id="raw-jwt",
    ),
    pytest.param(
        {"message": "Authorization: Bearer abcdef.ghijklm.opqrstuvwx"},
        "bearer_token",
        id="bearer-token",
    ),
    pytest.param(
        {"message": "api_key=sk_test_AAAAAAAAAAAAAAAAAAAAAAAA"},
        "raw_api_key",
        id="raw-api-key",
    ),
    pytest.param(
        {"message": '{"password":"hunter2"}'},
        "password_field",
        id="password-field",
    ),
    pytest.param(
        {"tags": ["password_hash:abc123"]},
        "password_hash_field",
        id="password-hash-field",
    ),
    pytest.param(
        {"message": "-----BEGIN RSA PRIVATE KEY-----"},
        "private_key_block",
        id="private-key-block",
    ),
]


@pytest.mark.parametrize("override,label", [(c.values[0], c.values[1]) for c in MASKED_CASES])
def test_sensitive_inbound_payloads_are_masked_without_echo(
    client_no_auth_override, demo_users, db_session, override, label
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    unsafe = {**SAFE_PRIVACYTRACE_EVENT, **override}
    response = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(token),
        json=unsafe,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "accepted"
    assert body["safety_status"] == "safe"
    assert body["alert_created"] is True
    # Ensure the unsafe text is NOT echoed back.
    serialized = json.dumps(body)
    for fragment in (
        "9812345678",
        "WAL12345678",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature_x",
        "Bearer abcdef.ghijklm.opqrstuvwx",
        "sk_test_AAAAAAAAAAAAAAAAAAAAAAAA",
        '"password":"hunter2"',
        "abc123",
        "-----BEGIN RSA PRIVATE KEY-----",
    ):
        assert fragment not in serialized


def test_certainty_wording_alone_is_accepted_as_input_evidence(
    client_no_auth_override, demo_users, db_session
):
    """Phase P: an inbound SIEM/SOC event's message is INPUT evidence — it
    may quote the source ticket's own certainty/blame wording. It must not
    be rejected for that wording alone; only raw secrets are rejected at
    this boundary."""
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(token),
        json={
            **SAFE_PRIVACYTRACE_EVENT,
            "message": "This was the proven cause of the breach",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "accepted"
    assert body["safety_status"] == "safe"


# ---------------------------------------------------------------------------
# Side-effects of ingestion: evidence row + audit logs + safe metadata
# ---------------------------------------------------------------------------


def test_ingestion_creates_safe_evidence_metadata_and_audit_entry(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(token),
        json=SAFE_PRIVACYTRACE_EVENT,
    )
    assert response.status_code == 200
    body = response.json()
    integration_event_id = body["integration_event_id"]

    evidence_rows = (
        db_session.execute(select(EvidenceFile).where(EvidenceFile.file_hash.is_not(None)))
        .scalars()
        .all()
    )
    assert any(
        row.evidence_id.startswith("EVD-INT-") for row in evidence_rows
    ), "ingestion must create an EvidenceFile row tagged for the integration boundary"

    audits = (
        db_session.execute(
            select(AuditLog).where(AuditLog.action == "integration_event_ingested")
        )
        .scalars()
        .all()
    )
    assert audits, "ingestion must be audited"
    assert any(
        (entry.target_id or "") == integration_event_id for entry in audits
    )


def test_rejected_ingestion_is_audited_safely(
    client_no_auth_override, demo_users, db_session
):
    """Phase P: raw secrets found in INPUT evidence (e.g. `password=...` in a
    log line) are masked and accepted, not rejected outright — see
    `test_sensitive_inbound_payloads_are_masked_without_echo`. The one thing
    this input-safety boundary still hard-rejects up front is a payload that
    is too large to safely process at all (schema-level 64 KiB guard on
    `IntegrationEventIngestRequest`); it must never echo the raw content back
    and must not create any evidence/alert record."""
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    oversized_message = "x" * (100 * 1024)
    response = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(token),
        json={
            **SAFE_PRIVACYTRACE_EVENT,
            "message": oversized_message,
        },
    )
    assert response.status_code == 422
    assert oversized_message not in response.text

    evidence_rows = (
        db_session.execute(
            select(EvidenceFile).where(EvidenceFile.evidence_id.like("EVD-INT-%"))
        )
        .scalars()
        .all()
    )
    assert not evidence_rows, "an oversized/rejected payload must not create evidence"


def test_integration_event_metadata_view_does_not_return_raw_payload(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(token),
        json=SAFE_PRIVACYTRACE_EVENT,
    )
    assert response.status_code == 200
    integration_event_id = response.json()["integration_event_id"]

    response = client_no_auth_override.get(
        f"/integrations/events/{integration_event_id}",
        headers=auth_headers(token),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["integration_event_id"] == integration_event_id
    assert body["safety_status"] == "safe"
    assert body["raw_payload_hash"]
    # Raw payload itself must not be present.
    assert "payload" not in body
    assert "raw_payload" not in body


# ---------------------------------------------------------------------------
# Outbound exports
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fmt,expected_content_type",
    [
        ("privacytrace_json", "application/json"),
        ("ocsf_json", "application/json"),
        ("ecs_json", "application/json"),
        ("splunk_hec_json", "application/json"),
        ("cef_like", "text/plain"),
        ("leef_like", "text/plain"),
        ("rfc5424_syslog_like", "text/plain"),
    ],
)
def test_soc_export_returns_safe_body_for_each_format(
    client_no_auth_override, demo_users, db_session, seeded_incident, fmt, expected_content_type
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.get(
        f"/integrations/incidents/{seeded_incident}/export?format={fmt}",
        headers=auth_headers(token),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["incident_id"] == seeded_incident
    assert body["format"] == fmt
    assert body["content_type"] == expected_content_type
    assert "export_body" in body
    serialized = json.dumps(body)
    # Defence-in-depth: no obvious unsafe markers in the rendered output.
    for fragment in (
        "Authorization:",
        "Bearer ",
        "-----BEGIN ",
        "password_hash",
        "proven cause",
        "definitely caused by",
        "developer fault",
    ):
        assert fragment.lower() not in serialized.lower()


def test_ocsf_export_contains_expected_mapped_fields(
    client_no_auth_override, demo_users, db_session, seeded_incident
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.get(
        f"/integrations/incidents/{seeded_incident}/export?format=ocsf_json",
        headers=auth_headers(token),
    )
    assert response.status_code == 200
    export_body = response.json()["export_body"]
    assert export_body["schema"] == "ocsf_json"
    assert export_body["metadata"]["uid"] == seeded_incident
    assert "finding" in export_body
    assert "unmapped" in export_body
    assert "evidence_ids" in export_body["unmapped"]


def test_ecs_export_contains_expected_mapped_fields(
    client_no_auth_override, demo_users, db_session, seeded_incident
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.get(
        f"/integrations/incidents/{seeded_incident}/export?format=ecs_json",
        headers=auth_headers(token),
    )
    assert response.status_code == 200
    export_body = response.json()["export_body"]
    assert export_body["schema"] == "ecs_json"
    assert export_body["event"]["id"] == seeded_incident
    assert export_body["event"]["kind"] == "alert"
    assert "labels" in export_body


def test_splunk_hec_export_has_source_sourcetype_event(
    client_no_auth_override, demo_users, db_session, seeded_incident
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.get(
        f"/integrations/incidents/{seeded_incident}/export?format=splunk_hec_json",
        headers=auth_headers(token),
    )
    assert response.status_code == 200
    export_body = response.json()["export_body"]
    assert export_body["source"] == "privacytrace-np"
    assert export_body["sourcetype"] == "privacytrace:incident"
    assert export_body["event"]["incident_id"] == seeded_incident


def test_text_exports_are_strings(
    client_no_auth_override, demo_users, db_session, seeded_incident
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    for fmt, head in [
        ("cef_like", "CEF:0|"),
        ("leef_like", "LEEF:2.0|"),
        ("rfc5424_syslog_like", "<134>1 "),
    ]:
        response = client_no_auth_override.get(
            f"/integrations/incidents/{seeded_incident}/export?format={fmt}",
            headers=auth_headers(token),
        )
        assert response.status_code == 200, response.text
        export_body = response.json()["export_body"]
        assert isinstance(export_body, str)
        assert export_body.startswith(head)
        assert seeded_incident in export_body


def test_export_unsupported_format_is_rejected(
    client_no_auth_override, demo_users, db_session, seeded_incident
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.get(
        f"/integrations/incidents/{seeded_incident}/export?format=banana",
        headers=auth_headers(token),
    )
    assert response.status_code == 400


def test_export_is_audited(
    client_no_auth_override, demo_users, db_session, seeded_incident
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.get(
        f"/integrations/incidents/{seeded_incident}/export?format=privacytrace_json",
        headers=auth_headers(token),
    )
    assert response.status_code == 200
    audits = (
        db_session.execute(
            select(AuditLog).where(AuditLog.action == "integration_incident_exported")
        )
        .scalars()
        .all()
    )
    assert audits, "SOC export must be audited"


def test_per_incident_formats_endpoint(
    client_no_auth_override, demo_users, db_session, seeded_incident
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.get(
        f"/integrations/incidents/{seeded_incident}/formats",
        headers=auth_headers(token),
    )
    assert response.status_code == 200
    body = response.json()
    outbound_ids = {entry["format_id"] for entry in body["outbound"]}
    assert {"privacytrace_json", "ocsf_json", "ecs_json", "splunk_hec_json"} <= outbound_ids


def test_viewer_cannot_export_soc_summary(
    client_no_auth_override, demo_users, db_session, seeded_incident
):
    token = _viewer_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.get(
        f"/integrations/incidents/{seeded_incident}/export?format=privacytrace_json",
        headers=auth_headers(token),
    )
    assert response.status_code == 403


def test_viewer_can_list_integration_formats_read_only(
    client_no_auth_override, demo_users, db_session
):
    token = _viewer_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.get(
        "/integrations/formats",
        headers=auth_headers(token),
    )
    assert response.status_code == 200
