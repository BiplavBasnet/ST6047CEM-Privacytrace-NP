from __future__ import annotations

import ast
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.models.enums import EvidenceType
from app.models.privacy_impact import PrivacyImpactFactor
from app.schemas.privacy_impact_schema import PrivacyImpactAssessRequest
from app.services import (
    breach_decision_service,
    evidence_provenance_service,
    ingestion_service,
    live_monitor_service,
    privacy_impact_service,
    scanner_bridge_service,
    siem_import_service,
)


class ScalarRows:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return self.rows


class FakeSession:
    def __init__(self, *, scalar_values=(), scalar_rows=()):
        self.scalar_values = iter(scalar_values)
        self.scalar_rows = iter(scalar_rows)
        self.added = []
        self.commits = 0
        self.flushes = 0

    def scalar(self, _statement):
        return next(self.scalar_values)

    def scalars(self, _statement):
        return ScalarRows(next(self.scalar_rows))

    def add(self, item):
        self.added.append(item)
        if isinstance(item, PrivacyImpactFactor) and item.id is None:
            item.id = len([row for row in self.added if isinstance(row, PrivacyImpactFactor)])

    def flush(self):
        self.flushes += 1

    def commit(self):
        self.commits += 1

    def refresh(self, _item):
        return None

    def rollback(self):
        return None


def settings():
    return SimpleNamespace(
        breach_credential_categories="access_token,api_key,password",
        breach_severity_medium_threshold=2.0,
        breach_severity_high_threshold=3.0,
        breach_severity_very_high_threshold=4.0,
        privacy_harm_medium_threshold=4,
        privacy_harm_high_threshold=8,
        privacy_harm_critical_threshold=12,
        nepal_financial_taxonomy_version="np-dfs-test",
        combined_exposure_ruleset_version="np-exposure-test",
    )


def test_provenance_service_has_one_authoritative_mutator_definition():
    source = Path(inspect.getsourcefile(evidence_provenance_service)).read_text(encoding="utf-8")
    names = [node.name for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)]

    assert names.count("record_system_provenance") == 1
    assert "commit" in inspect.signature(evidence_provenance_service.create_relationship).parameters
    assert "commit" in inspect.signature(evidence_provenance_service.validate_provenance).parameters


def test_parent_cycle_check_is_local_to_requested_evidence():
    edges = [("EVD-1", "EVD-2"), ("EVD-2", "EVD-1"), ("EVD-3", "EVD-4")]

    assert evidence_provenance_service.node_has_cycle(edges, "EVD-1") is True
    assert evidence_provenance_service.node_has_cycle(edges, "EVD-3") is False


def test_system_provenance_returns_record_and_respects_commit_owner(monkeypatch):
    record = SimpleNamespace(provenance_id="PRV-1")
    captured = {}
    db = FakeSession(scalar_values=[None])
    integrity_calls = []

    def fake_upsert(_db, _evidence_id, body, *, actor_id, commit):
        captured["body"] = body
        captured["actor_id"] = actor_id
        captured["commit"] = commit
        return record

    monkeypatch.setattr(evidence_provenance_service, "upsert_provenance", fake_upsert)
    monkeypatch.setattr(
        evidence_provenance_service,
        "append_evidence_integrity_record",
        lambda *_args, **_kwargs: integrity_calls.append(True),
    )

    result = evidence_provenance_service.record_system_provenance(
        db,
        "EVD-1",
        source_system="synthetic",
        source_format="json",
        collector_name="test",
        parser_name="synthetic_parser",
        parser_version="1",
        commit=False,
    )

    assert result is record
    assert captured["commit"] is False
    assert captured["body"].parser_version == "1"
    assert db.commits == 0
    assert integrity_calls == []

    evidence_provenance_service.record_system_provenance(
        db,
        "EVD-1",
        source_system="synthetic",
        source_format="json",
        collector_name="test",
        parser_name="synthetic_parser",
        parser_version="1",
        commit=False,
        append_integrity=True,
    )
    assert integrity_calls == [True]


def test_composed_mutators_default_to_caller_owned_transactions():
    assert (
        inspect.signature(evidence_provenance_service.upsert_provenance)
        .parameters["commit"]
        .default
        is False
    )
    assert (
        inspect.signature(evidence_provenance_service.create_relationship)
        .parameters["commit"]
        .default
        is False
    )
    assert (
        inspect.signature(evidence_provenance_service.validate_provenance)
        .parameters["commit"]
        .default
        is False
    )


def test_ingestion_passes_parser_metadata():
    source = inspect.getsource(ingestion_service.ingest_file)
    assert 'parser_name="file_ingestion"' in source
    assert 'parser_version="1"' in source
    assert "append_integrity=True" in source


def test_composed_provenance_callers_defer_commit_to_orchestrator():
    assert inspect.signature(live_monitor_service.process_event).parameters["commit"].default is True
    for module in (ingestion_service, live_monitor_service, scanner_bridge_service, siem_import_service):
        source = inspect.getsource(module)
        assert "record_system_provenance" in source
        assert "commit=False" in source
        assert "append_integrity=True" in source

    siem_source = inspect.getsource(siem_import_service.ingest_event)
    assert "commit=False" in siem_source
    assert siem_source.rindex("db.commit()") < siem_source.index("_store_canonical(record)")


def test_evidence_file_is_removed_when_provenance_fails(monkeypatch, tmp_path):
    db = FakeSession(scalar_values=[None, None])
    monkeypatch.setattr(ingestion_service, "_ensure_upload_dir", lambda: tmp_path)
    monkeypatch.setattr(ingestion_service.field_encryption_service, "encryption_enabled", lambda: False)
    monkeypatch.setattr(
        evidence_provenance_service,
        "record_system_provenance",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("synthetic provenance failure")),
    )

    with pytest.raises(RuntimeError, match="synthetic provenance failure"):
        ingestion_service.ingest_file(
            db,
            content=b"synthetic evidence",
            file_name="synthetic.log",
            evidence_type=EvidenceType.API_LOG,
            evidence_id="EVD-CLEANUP",
        )

    assert list(tmp_path.iterdir()) == []


def test_assessment_uses_config_versions_and_defers_commit(monkeypatch):
    incident = SimpleNamespace(incident_id="INC-1")
    detection = SimpleNamespace(detection_id="DET-1", sensitive_type="nepal_phone")
    db = FakeSession(scalar_values=[incident, None, 0], scalar_rows=[[detection], [], [], []])
    evaluated = []
    monkeypatch.setattr(privacy_impact_service, "get_settings", settings)
    monkeypatch.setattr(privacy_impact_service.audit_service, "log_action", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "app.services.privacy_breach_alert_service.evaluate_assessment",
        lambda _db, assessment, *, actor_id: evaluated.append((assessment, actor_id)),
    )

    assessment, created = privacy_impact_service.assess_incident(
        db,
        "INC-1",
        PrivacyImpactAssessRequest(),
        actor_id=7,
        commit=False,
    )

    assert created is True
    assert assessment.taxonomy_version == "np-dfs-test"
    assert assessment.combination_ruleset_version == "np-exposure-test"
    assert evaluated == [(assessment, 7)]
    assert db.commits == 0


def test_idempotent_assessment_still_reevaluates_alert(monkeypatch):
    incident = SimpleNamespace(incident_id="INC-1")
    existing = SimpleNamespace(assessment_id="PIA-1")
    detection = SimpleNamespace(detection_id="DET-1", sensitive_type="nepal_phone")
    db = FakeSession(scalar_values=[incident, existing], scalar_rows=[[detection], [], []])
    evaluated = []
    monkeypatch.setattr(privacy_impact_service, "get_settings", settings)
    monkeypatch.setattr(
        "app.services.privacy_breach_alert_service.evaluate_assessment",
        lambda _db, assessment, *, actor_id: evaluated.append((assessment, actor_id)),
    )

    result, created = privacy_impact_service.assess_incident(
        db,
        "INC-1",
        PrivacyImpactAssessRequest(),
        actor_id=7,
        commit=False,
    )

    assert result is existing
    assert created is False
    assert evaluated == [(existing, 7)]
    assert db.commits == 0


def test_approvers_must_be_independent_of_creator_and_reviewer():
    validators = (
        (privacy_impact_service.validate_approver_separation, privacy_impact_service.PrivacyImpactStateError),
        (breach_decision_service.validate_approver_separation, breach_decision_service.BreachDecisionStateError),
    )
    for validator, error in validators:
        with pytest.raises(error):
            validator(created_by=1, reviewed_by=2, actor_id=1)
        with pytest.raises(error):
            validator(created_by=1, reviewed_by=2, actor_id=2)
        validator(created_by=1, reviewed_by=2, actor_id=3)


def test_decision_integrity_reference_is_set_before_ledger_flush(monkeypatch):
    item = SimpleNamespace(
        decision_id="BDR-1",
        incident_id="INC-1",
        assessment_id="PIA-1",
        decision_version=1,
        status="reviewed",
        created_by=1,
        reviewed_by=2,
        approved_by=None,
        approved_at=None,
        integrity_record_id=None,
        breach_determination="confirmed",
    )
    assessment = SimpleNamespace(assessment_id="PIA-1")
    db = FakeSession(scalar_values=[assessment])
    evaluated = []
    monkeypatch.setattr(breach_decision_service, "_get", lambda *args, **kwargs: item)
    monkeypatch.setattr(
        breach_decision_service.integrity_ledger_service,
        "breach_decision_integrity_content",
        lambda decision: {"decision_id": decision.decision_id},
    )

    def append_record(_db, **kwargs):
        assert item.status == "approved"
        assert item.integrity_record_id == kwargs["integrity_record_id"]
        return SimpleNamespace(integrity_record_id=kwargs["integrity_record_id"])

    monkeypatch.setattr(breach_decision_service.integrity_ledger_service, "append_record", append_record)
    monkeypatch.setattr(breach_decision_service.audit_service, "log_action", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "app.services.privacy_breach_alert_service.evaluate_assessment",
        lambda _db, value, *, actor_id: evaluated.append((value, actor_id)),
    )

    result = breach_decision_service.approve_decision(
        db,
        "BDR-1",
        actor_id=3,
        reason="Independent synthetic approval.",
        commit=False,
    )

    assert result is item
    assert item.integrity_record_id.startswith("ILR-")
    assert evaluated == [(assessment, 3)]
    assert db.commits == 0
