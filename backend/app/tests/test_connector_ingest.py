"""Connector receiver: auth, spoof ignore, privacy reject, idempotency."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import func, select

from urllib.error import HTTPError

from app.dependencies import get_db_session
from app.main import app
from app.models.audit_log import AuditLog
from app.models.evidence_file import EvidenceFile
from app.models.evidence_provenance import EvidenceProvenance
from app.models.integration_event import IntegrationEvent
from app.models.integration_token import IntegrationToken
from app.schemas.connector_schema import CONNECTOR_PRIVACY_REJECTED
from app.services import siem_import_service
from app.tests.auth_test_utils import auth_headers, login, seed_demo_users_in_db

pytestmark = pytest.mark.usefixtures("migrated_db", "running_live_monitor")

ENDPOINT = "/integrations/connector/v1/events"
RAW_PHONE = "9841234567"


def _envelope(**overrides):
    body = {
        "specversion": "1.0",
        "id": "evt-runtime-001",
        "source": "/nepalfin/payments",
        "type": "np.privacytrace.runtime.event.v1",
        "time": "2026-08-16T12:00:00Z",
        "datacontenttype": "application/json",
        "data": {
            "service": "payments",
            "route_template": "/v1/transfer",
            "environment": "test",
            "message_summary": "health check",
        },
    }
    body.update(overrides)
    return body


@pytest.fixture(autouse=True)
def gateway_db_override(db_session):
    def _override():
        yield db_session

    app.dependency_overrides[get_db_session] = _override
    siem_import_service.clear_event_store()
    yield
    siem_import_service.clear_event_store()
    app.dependency_overrides.pop(get_db_session, None)


@pytest.fixture
def demo_users(db_session):
    return seed_demo_users_in_db(db_session)


@pytest.fixture
def client_no_auth_override(client):
    from app.dependencies.auth_dependencies import get_current_user

    app.dependency_overrides.pop(get_current_user, None)
    yield client
    app.dependency_overrides.pop(get_current_user, None)


def _admin_token(client, demo_users, db_session) -> str:
    db_session.commit()
    return login(client, email="admin@privacytrace.local", password="AdminPass123!")


def _mint_ingest_token(
    client, demo_users, db_session, *, source_name: str = "token-bound-source"
) -> str:
    admin = _admin_token(client, demo_users, db_session)
    created = client.post(
        "/integrations/tokens",
        headers=auth_headers(admin),
        json={"name": "runtime-connector", "source_name": source_name},
    )
    assert created.status_code == 200, created.text
    return created.json()["token"]


def test_missing_token_is_unauthorized(client_no_auth_override, demo_users, db_session):
    response = client_no_auth_override.post(ENDPOINT, json=_envelope())
    assert response.status_code == 401


def test_source_spoof_ignored_and_event_accepted(
    client_no_auth_override, demo_users, db_session
):
    token = _mint_ingest_token(
        client_no_auth_override, demo_users, db_session, source_name="nepalfin-runtime"
    )
    declared = "/fake/wazuh/source"
    response = client_no_auth_override.post(
        ENDPOINT,
        headers=auth_headers(token),
        json=_envelope(source=declared),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "accepted"
    assert body["event_id"]
    assert body["evidence_id"]
    dumped = json.dumps(body)
    assert declared not in dumped
    row = db_session.scalar(select(IntegrationEvent))
    assert row is not None
    assert row.source_name == "nepalfin-runtime"
    assert row.client_event_id == "evt-runtime-001"
    provenance = db_session.scalar(select(EvidenceProvenance))
    assert provenance is not None
    assert provenance.source_system == "nepalfin-runtime"
    assert provenance.source_system != declared
    assert provenance.source_event_id == "evt-runtime-001"
    evidence = db_session.scalar(select(EvidenceFile))
    assert evidence is not None
    assert evidence.source_system == "nepalfin-runtime"
    assert evidence.evidence_type.value == "runtime_log"
    assert RAW_PHONE not in dumped


def test_privacy_reject_does_not_persist_or_echo(
    client_no_auth_override, demo_users, db_session
):
    token = _mint_ingest_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        ENDPOINT,
        headers=auth_headers(token),
        json=_envelope(
            id="evt-raw",
            data={"message_summary": f"phone {RAW_PHONE}"},
        ),
    )
    assert response.status_code == 422, response.text
    body = response.json()
    dumped = json.dumps(body)
    assert RAW_PHONE not in dumped
    assert body.get("reason") == CONNECTOR_PRIVACY_REJECTED or CONNECTOR_PRIVACY_REJECTED in dumped
    assert db_session.scalar(select(func.count(IntegrationEvent.id))) == 0
    assert db_session.scalar(select(func.count(EvidenceFile.id))) == 0
    audits = list(db_session.scalars(select(AuditLog)).all())
    assert RAW_PHONE not in json.dumps(
        [{"action": a.action, "details": a.details} for a in audits], default=str
    )


def test_idempotent_replay_returns_duplicate(
    client_no_auth_override, demo_users, db_session
):
    token = _mint_ingest_token(client_no_auth_override, demo_users, db_session)
    first = client_no_auth_override.post(
        ENDPOINT, headers=auth_headers(token), json=_envelope()
    )
    assert first.status_code == 200, first.text
    second = client_no_auth_override.post(
        ENDPOINT, headers=auth_headers(token), json=_envelope()
    )
    assert second.status_code == 200, second.text
    assert second.json()["status"] == "duplicate"
    assert second.json()["event_id"] == first.json()["event_id"]
    assert second.json()["evidence_id"] == first.json()["evidence_id"]
    assert db_session.scalar(select(func.count(IntegrationEvent.id))) == 1
    assert db_session.scalar(select(func.count(EvidenceFile.id))) == 1


def test_revoked_token_rejected(client_no_auth_override, demo_users, db_session):
    admin = _admin_token(client_no_auth_override, demo_users, db_session)
    created = client_no_auth_override.post(
        "/integrations/tokens",
        headers=auth_headers(admin),
        json={"name": "to-revoke", "source_name": "revoked-source"},
    )
    raw = created.json()["token"]
    token_id = created.json()["token_id"]
    revoked = client_no_auth_override.delete(
        f"/integrations/tokens/{token_id}", headers=auth_headers(admin)
    )
    assert revoked.status_code == 200
    response = client_no_auth_override.post(
        ENDPOINT, headers=auth_headers(raw), json=_envelope()
    )
    assert response.status_code == 401
    record = db_session.scalar(
        select(IntegrationToken).where(IntegrationToken.token_id == token_id)
    )
    assert record is not None and record.is_active is False


def test_runtime_connector_emit_creates_evidence(
    client_no_auth_override, demo_users, db_session, monkeypatch
):
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(root))
    from connectors.runtime.client import RuntimeConnector
    from app.schemas.connector_schema import ConnectorEventData

    token = _mint_ingest_token(client_no_auth_override, demo_users, db_session)

    def fake_urlopen(request, timeout=None):
        auth = request.get_header("Authorization") or f"Bearer {token}"
        resp = client_no_auth_override.post(
            "/integrations/connector/v1/events",
            headers={"Authorization": auth, "Content-Type": "application/json"},
            content=request.data,
        )

        class _Resp:
            status = resp.status_code

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

        if resp.status_code >= 400:
            raise HTTPError(
                request.full_url, resp.status_code, "rejected", hdrs=None, fp=None
            )
        return _Resp()

    monkeypatch.setattr("privacytrace_runtime.client.urlopen", fake_urlopen)
    connector = RuntimeConnector(
        "http://127.0.0.1/integrations/connector/v1/events",
        token,
        "/nepalfin/payments",
    )
    ok = connector.emit(
        data=ConnectorEventData(
            service="payments",
            route_template="/v1/transfer",
            message_summary="runtime health",
        ),
        event_id="evt-runtime-emit-1",
    )
    assert ok is True
    assert connector.health()["dropped"] == 0
    row = db_session.scalar(
        select(IntegrationEvent).where(IntegrationEvent.client_event_id == "evt-runtime-emit-1")
    )
    assert row is not None
    assert row.evidence_reference
    evidence = db_session.scalar(
        select(EvidenceFile).where(EvidenceFile.evidence_id == row.evidence_reference)
    )
    assert evidence is not None
    assert evidence.evidence_type.value == "runtime_log"


def test_wazuh_synthetic_file_creates_evidence(
    client_no_auth_override, demo_users, db_session
):
    import importlib.machinery
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    loader = importlib.machinery.SourceFileLoader(
        "custom_privacytrace", str(root / "connectors" / "wazuh" / "custom-privacytrace")
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    alert = json.loads(
        (root / "connectors" / "wazuh" / "synthetic-alert.json").read_text(encoding="utf-8")
    )
    envelope = module.map_alert(alert)
    token = _mint_ingest_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        ENDPOINT, headers=auth_headers(token), json=envelope
    )
    assert response.status_code == 200, response.text
    assert RAW_PHONE not in response.text
    assert "full_log" not in response.text
    body = response.json()
    assert body["status"] == "accepted"
    evidence = db_session.scalar(select(EvidenceFile))
    assert evidence is not None
    assert evidence.evidence_type.value == "siem_alert"


def test_same_client_event_id_different_source_is_accepted(
    client_no_auth_override, demo_users, db_session
):
    admin = _admin_token(client_no_auth_override, demo_users, db_session)
    first_token = client_no_auth_override.post(
        "/integrations/tokens",
        headers=auth_headers(admin),
        json={"name": "source-a-connector", "source_name": "source-a"},
    )
    second_token = client_no_auth_override.post(
        "/integrations/tokens",
        headers=auth_headers(admin),
        json={"name": "source-b-connector", "source_name": "source-b"},
    )
    assert first_token.status_code == 200, first_token.text
    assert second_token.status_code == 200, second_token.text
    envelope = _envelope(id="shared-client-event")
    first = client_no_auth_override.post(
        ENDPOINT, headers=auth_headers(first_token.json()["token"]), json=envelope
    )
    second = client_no_auth_override.post(
        ENDPOINT, headers=auth_headers(second_token.json()["token"]), json=envelope
    )
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()["status"] == "accepted"
    assert second.json()["status"] == "accepted"
    assert first.json()["event_id"] != second.json()["event_id"]
    assert db_session.scalar(select(func.count(IntegrationEvent.id))) == 2


def test_viewer_cannot_create_or_revoke_tokens(
    client_no_auth_override, demo_users, db_session
):
    db_session.commit()
    viewer = login(
        client_no_auth_override,
        email="viewer@privacytrace.local",
        password="ViewerPass123!",
    )
    created = client_no_auth_override.post(
        "/integrations/tokens",
        headers=auth_headers(viewer),
        json={"name": "viewer-token", "source_name": "viewer-source"},
    )
    assert created.status_code == 403
    admin = _admin_token(client_no_auth_override, demo_users, db_session)
    minted = client_no_auth_override.post(
        "/integrations/tokens",
        headers=auth_headers(admin),
        json={"name": "admin-minted", "source_name": "admin-source"},
    )
    assert minted.status_code == 200, minted.text
    revoked = client_no_auth_override.delete(
        f"/integrations/tokens/{minted.json()['token_id']}",
        headers=auth_headers(viewer),
    )
    assert revoked.status_code == 403
    record = db_session.scalar(
        select(IntegrationToken).where(
            IntegrationToken.token_id == minted.json()["token_id"]
        )
    )
    assert record is not None and record.is_active is True

