"""Connector V1 contract: CloudEvents-inspired envelope, extra=forbid, 64 KiB cap."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.connector_schema import (
    ConnectorEventData,
    ConnectorEventEnvelope,
    ConnectorEventType,
    connector_json_schema,
)

SCHEMA_PATH = (
    Path(__file__).resolve().parents[3] / "docs" / "contracts" / "connector-event-v1.json"
)


def _valid(**overrides):
    body = {
        "specversion": "1.0",
        "id": "evt-001",
        "source": "/nepalfin/payments",
        "type": ConnectorEventType.RUNTIME_EVENT.value,
        "datacontenttype": "application/json",
        "data": {"service": "payments", "route_template": "/v1/transfer", "message_summary": "ok"},
    }
    body.update(overrides)
    return body


def test_valid_envelope_parses():
    event = ConnectorEventEnvelope.model_validate(_valid())
    assert event.id == "evt-001"
    assert event.data.service == "payments"


def test_unknown_top_level_field_rejected():
    with pytest.raises(ValidationError):
        ConnectorEventEnvelope.model_validate(_valid(full_log="nope"))


def test_unknown_data_field_rejected():
    body = _valid()
    body["data"] = {**body["data"], "headers": {"Authorization": "secret"}}
    with pytest.raises(ValidationError):
        ConnectorEventEnvelope.model_validate(body)


def test_required_cloudevents_fields():
    for field in ("specversion", "id", "source", "type"):
        body = _valid()
        body.pop(field)
        with pytest.raises(ValidationError):
            ConnectorEventEnvelope.model_validate(body)


def test_route_template_rejects_full_url():
    body = _valid()
    body["data"] = {**body["data"], "route_template": "https://api.example/v1/transfer?card=1"}
    with pytest.raises(ValidationError):
        ConnectorEventEnvelope.model_validate(body)


def test_source_rejects_query_string():
    with pytest.raises(ValidationError):
        ConnectorEventEnvelope.model_validate(_valid(source="/svc?token=abc"))


def test_finite_event_types():
    with pytest.raises(ValidationError):
        ConnectorEventEnvelope.model_validate(_valid(type="com.example.unknown"))


def test_size_limit_64kib():
    huge = ConnectorEventEnvelope.model_construct(
        specversion="1.0",
        id="evt-big",
        source="/s",
        type=ConnectorEventType.RUNTIME_EVENT,
        datacontenttype="application/json",
        data=ConnectorEventData.model_construct(message_summary="x" * (65 * 1024)),
    )
    with pytest.raises(ValueError, match="64 KiB"):
        huge.enforce_size()


def test_json_schema_artifact_matches_model():
    assert SCHEMA_PATH.is_file()
    on_disk = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert on_disk == connector_json_schema()


def test_runtime_connector_event_data_fields_match_backend():
    import sys

    sys.path.insert(0, str(SCHEMA_PATH.parents[2] / "connectors" / "runtime" / "src"))
    from privacytrace_runtime.schemas import ConnectorEventData as RuntimeData
    from privacytrace_runtime.schemas import ConnectorEventType as RuntimeType

    assert set(RuntimeData.model_fields) == set(ConnectorEventData.model_fields)
    assert {item.value for item in RuntimeType} == {item.value for item in ConnectorEventType}
