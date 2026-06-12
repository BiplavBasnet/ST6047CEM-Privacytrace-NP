"""Connector adapters: runtime sanitise, Wazuh allowlist, GitHub JS contract."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

from app.schemas.connector_schema import ConnectorEventData, ConnectorEventEnvelope
from app.services.connector_ingest_service import privacy_gate, ConnectorPrivacyRejected
import pytest

ROOT = Path(__file__).resolve().parents[3]
WAZUH = ROOT / "connectors" / "wazuh" / "custom-privacytrace"
GITHUB_TEST = ROOT / "connectors" / "github-actions" / "test.js"
RAW_PHONE = "9841234567"


def _load_wazuh():
    loader = importlib.machinery.SourceFileLoader("custom_privacytrace", str(WAZUH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_privacy_gate_rejects_residual_secret():
    envelope = ConnectorEventEnvelope.model_validate(
        {
            "specversion": "1.0",
            "id": "evt-raw",
            "source": "/nepalfin/payments",
            "type": "np.privacytrace.runtime.event.v1",
            "data": {"message_summary": f"customer phone {RAW_PHONE}"},
        }
    )
    with pytest.raises(ConnectorPrivacyRejected):
        privacy_gate(envelope)


def test_privacy_gate_allows_already_masked():
    envelope = ConnectorEventEnvelope.model_validate(
        {
            "specversion": "1.0",
            "id": "evt-masked",
            "source": "/nepalfin/payments",
            "type": "np.privacytrace.runtime.event.v1",
            "data": {
                "message_summary": "customer phone 98******67",
                "masked_value": "98******67",
                "sensitive_type": "phone_number",
            },
        }
    )
    privacy_gate(envelope)


def test_runtime_sanitize_strips_raw_before_transport():
    sys.path.insert(0, str(ROOT))
    from connectors.runtime.client import sanitize_data

    safe, is_exposure = sanitize_data(
        ConnectorEventData(message_summary=f"leak {RAW_PHONE}", service="payments")
    )
    assert is_exposure is True
    dumped = json.dumps(safe.model_dump())
    assert RAW_PHONE not in dumped
    assert safe.masked_value
    assert "withheld" in (safe.message_summary or "")


def test_wazuh_mapper_drops_full_log_and_data():
    module = _load_wazuh()
    alert = json.loads((ROOT / "connectors" / "wazuh" / "synthetic-alert.json").read_text(encoding="utf-8"))
    envelope = module.map_alert(alert)
    blob = json.dumps(envelope)
    assert "full_log" not in envelope["data"]
    assert "full_log" not in envelope
    assert RAW_PHONE not in blob
    assert "should-never-be-copied" not in blob
    assert envelope["type"] == "np.privacytrace.wazuh.alert.v1"
    assert envelope["data"]["rule_id"] == "550"
    ConnectorEventEnvelope.model_validate(envelope)


def test_github_action_contract():
    result = subprocess.run(
        ["node", str(GITHUB_TEST)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "github-actions contract ok" in result.stdout


API_KEY = "sk_test_AAAAAAAAAAAAAAAAAAAAAAAA"
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.sig"
BEARER = f"Bearer {JWT}"


def _runtime_connector(monkeypatch, *, queue_max=100, post_impl=None):
    sys.path.insert(0, str(ROOT))
    from connectors.runtime.client import RuntimeConnector

    posts: list[dict] = []

    def _post(self, body):
        posts.append(body)
        if post_impl is not None:
            return post_impl(body)
        return True

    monkeypatch.setattr(RuntimeConnector, "_post", _post)
    connector = RuntimeConnector(
        "http://127.0.0.1/integrations/connector/v1/events",
        "ptig_test",
        "nepalfin-runtime",
        queue_max=queue_max,
    )
    return connector, posts


def test_privacy_drop_api_key_in_component_skips_transport(monkeypatch):
    connector, posts = _runtime_connector(monkeypatch)
    ok = connector.emit(data={"component": API_KEY, "message_summary": "health"})
    assert ok is False
    assert posts == []
    health = connector.health()
    assert health["queued"] == 0
    assert health["dropped"] == 1
    assert health["last_failure_reason"] == "privacy_drop"
    assert API_KEY not in json.dumps(health)


def test_privacy_drop_bearer_in_request_id_skips_transport(monkeypatch):
    connector, posts = _runtime_connector(monkeypatch)
    ok = connector.emit(data={"request_id": BEARER, "message_summary": "health"})
    assert ok is False
    assert posts == []
    health = connector.health()
    assert health["queued"] == 0
    assert health["dropped"] == 1
    assert JWT not in json.dumps(health)
    assert "Bearer " not in json.dumps(health)


def test_safe_fields_call_http(monkeypatch):
    connector, posts = _runtime_connector(monkeypatch)
    ok = connector.emit(
        data={
            "service": "payments",
            "environment": "test",
            "message_summary": "Synthetic runtime event. No customer data.",
        }
    )
    assert ok is True
    assert len(posts) == 1
    blob = json.dumps(posts[0])
    assert "Synthetic runtime event" in blob
    assert API_KEY not in blob


def test_emit_accepts_native_runtime_model(monkeypatch):
    sys.path.insert(0, str(ROOT / "connectors" / "runtime" / "src"))
    from privacytrace_runtime.schemas import ConnectorEventData as RuntimeData

    connector, posts = _runtime_connector(monkeypatch)
    ok = connector.emit(
        data=RuntimeData(service="payments", message_summary="native runtime model")
    )
    assert ok is True
    assert posts[0]["data"]["message_summary"] == "native runtime model"


def test_emit_accepts_foreign_pydantic_model(monkeypatch):
    connector, posts = _runtime_connector(monkeypatch)
    ok = connector.emit(
        data=ConnectorEventData(service="payments", message_summary="foreign backend model")
    )
    assert ok is True
    assert posts[0]["data"]["message_summary"] == "foreign backend model"


def test_emit_rejects_invalid_object_without_send(monkeypatch):
    connector, posts = _runtime_connector(monkeypatch)
    ok = connector.emit(data=object())
    assert ok is False
    assert posts == []
    health = connector.health()
    assert health["last_failure_reason"] == "emit_error"
    assert health["dropped"] == 1
    blob = json.dumps(health)
    assert "ptig_test" not in blob
    assert "traceback" not in blob.lower()


def test_transformable_message_summary_posts_sanitised_body(monkeypatch):
    connector, posts = _runtime_connector(monkeypatch)
    ok = connector.emit(data={"message_summary": f"leak {RAW_PHONE}", "service": "payments"})
    assert ok is True
    assert len(posts) == 1
    blob = json.dumps(posts[0])
    assert RAW_PHONE not in blob
    assert "withheld" in blob
    assert posts[0]["data"].get("masked_value")


def test_health_unknown_then_available_after_success(monkeypatch):
    sys.path.insert(0, str(ROOT))
    from connectors.runtime.client import RuntimeConnector

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    monkeypatch.setattr("privacytrace_runtime.client.urlopen", lambda *_a, **_k: _Resp())
    connector = RuntimeConnector("http://127.0.0.1/x", "tok", "src")
    assert connector.health()["available"] == "UNKNOWN"
    assert connector.emit(data={"message_summary": "ok"}) is True
    assert connector.health()["available"] == "AVAILABLE"


def test_health_unavailable_on_timeout_and_transport(monkeypatch):
    sys.path.insert(0, str(ROOT))
    from urllib.error import URLError
    from connectors.runtime.client import RuntimeConnector

    monkeypatch.setattr(
        "privacytrace_runtime.client.urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError()),
    )
    timed = RuntimeConnector("http://127.0.0.1/x", "tok", "src")
    assert timed.emit(data={"message_summary": "retry-me"}) is False
    health = timed.health()
    assert health["available"] == "UNAVAILABLE"
    assert health["last_failure_reason"] == "timeout"
    assert health["queued"] == 1
    assert "retry-me" not in json.dumps(health)

    monkeypatch.setattr(
        "privacytrace_runtime.client.urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(URLError("down")),
    )
    down = RuntimeConnector("http://127.0.0.1/x", "tok", "src")
    assert down.emit(data={"message_summary": "later"}) is False
    assert down.health()["available"] == "UNAVAILABLE"
    assert down.health()["last_failure_reason"] == "transport_error"


def test_queue_flush_and_bound_drop(monkeypatch):
    sent = {"n": 0}

    def flaky(_self, _body):
        sent["n"] += 1
        return sent["n"] > 1

    connector, _posts = _runtime_connector(monkeypatch, queue_max=2, post_impl=lambda body: flaky(None, body))
    assert connector.emit(data={"message_summary": "one"}) is False
    assert connector.health()["queued"] == 1
    assert connector.flush() == 1
    assert connector.health()["queued"] == 0

    bounded, _ = _runtime_connector(monkeypatch, queue_max=2, post_impl=lambda _body: False)
    for i in range(3):
        bounded.emit(data={"message_summary": f"event-{i}"})
    health = bounded.health()
    assert health["queued"] == 2
    assert health["dropped"] >= 1


def test_wazuh_mapper_omits_location_from_route_template():
    module = _load_wazuh()
    location = "/var/log/nepalfin/application.log"
    envelope = module.map_alert(
        {
            "id": "loc-1",
            "timestamp": "2026-08-16T12:00:00.000Z",
            "location": location,
            "full_log": f"customer phone {RAW_PHONE}",
            "data": {"should-never-be-copied": "secret-field"},
            "rule": {"id": "550", "level": 10, "groups": ["syscheck"]},
            "agent": {"name": "wazuh-agent"},
        }
    )
    data = envelope["data"]
    assert data.get("route_template") != location
    assert "route_template" not in data
    blob = json.dumps(envelope)
    assert location not in blob
    assert RAW_PHONE not in blob
    assert "should-never-be-copied" not in blob
    assert "full_log" not in envelope
    assert "full_log" not in data
    ConnectorEventEnvelope.model_validate(envelope)
