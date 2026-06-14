from types import SimpleNamespace

from app.services import final_report_service
from app.services import report_service
from app.services import workflow_provenance_service
from app.schemas.final_report_schema import FinalReportMetadata


class _ScalarResult:
    def __init__(self, value):
        self.value = value


class _Db:
    bind = None

    def scalar(self, _statement):
        return 7


def test_lifecycle_ids_come_from_one_exact_chain(monkeypatch):
    analysis = SimpleNamespace(
        analysis_id="RCA-CURRENT",
        analysis_version=3,
        evidence_snapshot_hash="snapshot-current",
        taxonomy_version="taxonomy-v3",
        exposure_policy_version="exposure-v2",
    )
    review = SimpleNamespace(id=33)
    diagnosis = SimpleNamespace(
        diagnosis_id="DIAG-CURRENT", recommendation_policy_version="policy-v4"
    )
    action = SimpleNamespace(remediation_action_id="ACT-CURRENT")
    implementation = SimpleNamespace(implementation_id="IMPL-CURRENT")
    patch = SimpleNamespace(patch_proposal_id="PATCH-CURRENT")
    execution = SimpleNamespace(execution_id="TEST-CURRENT")
    retest = SimpleNamespace(controlled_retest_id="RETEST-CURRENT")
    fix = SimpleNamespace(id=44)
    outcome = SimpleNamespace(verification_outcome_id="OUT-CURRENT")
    chain = {
        "workflow_chain_status": "current_complete",
        "blocked_reasons": [],
        "analysis": analysis,
        "review": review,
        "diagnosis": diagnosis,
        "action": action,
        "implementation": implementation,
        "patch": patch,
        "test_execution": execution,
        "controlled_retest": retest,
        "fix_verification": fix,
        "outcome": outcome,
    }
    monkeypatch.setattr(
        final_report_service.workflow_provenance_service,
        "get_exact_report_chain",
        lambda db, incident_id: chain,
    )

    result = final_report_service._lifecycle_ids(_Db(), "INC-1")

    assert result["report_version"] == 8
    assert result["review_decision_id"] == 33
    assert result["implementation_id"] == "IMPL-CURRENT"
    assert result["controlled_retest_id"] == "RETEST-CURRENT"
    assert result["verification_outcome_id"] == "OUT-CURRENT"
    assert result["recommendation_policy_version"] == "policy-v4"


def test_blocked_chain_exposes_no_unvalidated_descendant_ids(monkeypatch):
    chain = {
        "workflow_chain_status": "blocked",
        "blocked_reasons": ["cross-branch"],
        "analysis": SimpleNamespace(
            analysis_id="RCA-CURRENT",
            analysis_version=2,
            evidence_snapshot_hash="snapshot",
            taxonomy_version=None,
            exposure_policy_version=None,
        ),
        "review": None,
        "diagnosis": None,
        "action": None,
        "implementation": None,
        "patch": None,
        "test_execution": None,
        "controlled_retest": None,
        "fix_verification": None,
        "outcome": None,
    }
    monkeypatch.setattr(
        final_report_service.workflow_provenance_service,
        "get_exact_report_chain",
        lambda db, incident_id: chain,
    )
    result = final_report_service._lifecycle_ids(_Db(), "INC-1")
    assert result["root_cause_analysis_id"] == "RCA-CURRENT"
    assert result["review_decision_id"] is None
    assert result["remediation_action_id"] is None
    assert result["verification_outcome_id"] is None
    assert result["blocked_reasons"] == ["cross-branch"]


def test_final_export_uses_configured_encryption_without_plaintext(monkeypatch):
    class Db:
        def __init__(self):
            self.row = None

        def add(self, row):
            self.row = row

        def flush(self):
            return None

    report = SimpleNamespace(
        metadata=FinalReportMetadata(
            incident_id="INC-1",
            generated_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
            report_format="json",
            workflow_chain_status="current_complete",
        ),
        model_dump=lambda mode: {"safe": "masked-only"},
    )
    monkeypatch.setattr(
        final_report_service.field_encryption_service, "encryption_enabled", lambda: True
    )
    monkeypatch.setattr(
        final_report_service.field_encryption_service,
        "encrypt_json",
        lambda **kwargs: {"kid": "test-key", "ciphertext": "encrypted"},
    )
    db = Db()
    row = final_report_service.persist_final_report_export(db, report)
    assert row.content_json is None
    assert row.content_encrypted == {"kid": "test-key", "ciphertext": "encrypted"}
    assert row.is_encrypted is True
    assert "masked-only" not in str(row.content_encrypted)


def test_two_persisted_exports_keep_versions_and_newest_match_is_current(monkeypatch):
    class Db:
        def __init__(self):
            self.rows = []

        def add(self, row):
            row.id = len(self.rows) + 1
            self.rows.append(row)

        def flush(self):
            return None

    monkeypatch.setattr(
        final_report_service.field_encryption_service, "encryption_enabled", lambda: False
    )
    db = Db()
    for version in (1, 2):
        metadata = FinalReportMetadata(
            incident_id="INC-1",
            generated_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
            report_format="json",
            report_version=version,
            root_cause_analysis_id="RCA-1",
            root_cause_analysis_version=1,
            evidence_snapshot_hash="snap-1",
            verification_outcome_id="OUT-1",
            workflow_chain_status="current_complete",
        )
        final_report_service.persist_final_report_export(
            db, SimpleNamespace(metadata=metadata, model_dump=lambda mode: {"safe": "masked"})
        )
    analysis = SimpleNamespace(
        analysis_id="RCA-1", analysis_version=1, evidence_snapshot_hash="snap-1"
    )
    outcome = SimpleNamespace(verification_outcome_id="OUT-1")
    monkeypatch.setattr(
        "app.services.workflow_provenance_service.get_exact_report_chain",
        lambda db, incident_id: {
            "workflow_chain_status": "current_complete", "analysis": analysis, "outcome": outcome
        },
    )
    statuses = report_service.report_history_statuses(db, "INC-1", db.rows)
    assert [row.report_version for row in db.rows] == [1, 2]
    assert statuses[1]["history_status"] == "superseded_export"
    assert statuses[2]["history_status"] == "current_export"


def test_report_source_does_not_infer_exposure_policy_result_from_retest():
    source = __import__("inspect").getsource(
        final_report_service.build_final_investigation_report
    )
    assert '"exposure_policy_result": "not_recorded"' in source
    assert "original exposure-policy decision is not persisted" in source


def test_report_history_uses_exact_chain_not_list_position(monkeypatch):
    analysis = SimpleNamespace(
        analysis_id="RCA-CURRENT", analysis_version=2, evidence_snapshot_hash="snapshot-2"
    )
    outcome = SimpleNamespace(verification_outcome_id="OUT-CURRENT")
    rows = [
        SimpleNamespace(
            id=30, report_version=3, report_type="final_json",
            root_cause_analysis_id="RCA-OLD", root_cause_analysis_version=1,
            evidence_snapshot_hash="snapshot-1", verification_outcome_id="OUT-OLD",
            workflow_chain_status="current_complete",
        ),
        SimpleNamespace(
            id=20, report_version=2, report_type="final_pdf",
            root_cause_analysis_id="RCA-CURRENT", root_cause_analysis_version=2,
            evidence_snapshot_hash="snapshot-2", verification_outcome_id="OUT-CURRENT",
            workflow_chain_status="current_complete",
        ),
        SimpleNamespace(
            id=10, report_version=1, report_type="json",
            root_cause_analysis_id=None, root_cause_analysis_version=None,
            evidence_snapshot_hash=None, verification_outcome_id=None,
            workflow_chain_status="blocked",
        ),
    ]
    monkeypatch.setattr(
        "app.services.workflow_provenance_service.get_exact_report_chain",
        lambda db, incident_id: {
            "workflow_chain_status": "current_complete", "analysis": analysis, "outcome": outcome
        },
    )
    statuses = report_service.report_history_statuses(object(), "INC-1", rows)
    assert statuses[20] == {
        "history_status": "current_export", "current_chain_match_at_export": True
    }
    assert statuses[30]["history_status"] == "superseded_export"
    assert statuses[10]["history_status"] == "historical_report"


def test_false_positive_export_matches_exact_review_without_outcome(monkeypatch):
    analysis = SimpleNamespace(
        analysis_id="RCA-FP", analysis_version=2, evidence_snapshot_hash="snapshot-fp"
    )
    review = SimpleNamespace(id=81)
    row = SimpleNamespace(
        id=9, report_version=1, report_type="final_json",
        root_cause_analysis_id="RCA-FP", root_cause_analysis_version=2,
        evidence_snapshot_hash="snapshot-fp", review_decision_id=81,
        verification_outcome_id=None, workflow_chain_status="current_false_positive",
    )
    monkeypatch.setattr(
        "app.services.workflow_provenance_service.get_exact_report_chain",
        lambda db, incident_id: {
            "workflow_chain_status": "current_false_positive", "analysis": analysis,
            "review": review, "outcome": None,
        },
    )
    status = report_service.report_history_statuses(object(), "INC-1", [row])[9]
    assert status == {
        "history_status": "current_export", "current_chain_match_at_export": True
    }


def test_partial_resolver_drops_interleaved_action_and_descendants(monkeypatch):
    current = SimpleNamespace(
        analysis_id="RCA-2", analysis_version=2, evidence_snapshot_hash="snap-2",
        stale=False, current=True,
    )
    review = SimpleNamespace(
        id=12, incident_id="INC-1", root_cause_analysis_id="RCA-2",
        root_cause_analysis_version=2, evidence_snapshot_hash="snap-2",
        decision="approved", progression_valid=True,
    )
    diagnosis = SimpleNamespace(diagnosis_id="DIAG-2")
    interleaved_action = SimpleNamespace(
        remediation_action_id="ACT-OLD", root_cause_analysis_id="RCA-OLD",
        review_decision_id=12, diagnosis_id="DIAG-2",
    )

    class Db:
        bind = None

        def __init__(self):
            self.values = iter([None, None, review, diagnosis, interleaved_action])

        def scalar(self, _statement):
            return next(self.values)

    monkeypatch.setattr(
        workflow_provenance_service.root_cause_analysis_service,
        "get_current_analysis",
        lambda db, incident_id: current,
    )
    chain = workflow_provenance_service.get_exact_report_chain(Db(), "INC-1")
    assert chain["workflow_chain_status"] == "current_incomplete"
    assert chain["diagnosis"] is diagnosis
    assert chain["action"] is None
    assert chain["implementation"] is None
    assert chain["patch"] is None


def test_partial_resolver_drops_cross_parent_patch(monkeypatch):
    current = SimpleNamespace(
        analysis_id="RCA-2", analysis_version=2, evidence_snapshot_hash="snap-2",
        stale=False, current=True,
    )
    review = SimpleNamespace(
        id=12, incident_id="INC-1", root_cause_analysis_id="RCA-2",
        root_cause_analysis_version=2, evidence_snapshot_hash="snap-2",
        decision="approved", progression_valid=True,
    )
    diagnosis = SimpleNamespace(diagnosis_id="DIAG-2")
    action = SimpleNamespace(
        remediation_action_id="ACT-2", root_cause_analysis_id="RCA-2",
        review_decision_id=12, diagnosis_id="DIAG-2",
    )
    implementation = SimpleNamespace(
        implementation_id="IMPL-2", root_cause_analysis_id="RCA-2",
        review_decision_id=12, diagnosis_id="DIAG-2", remediation_action_id="ACT-2",
    )
    test = SimpleNamespace(
        execution_id="TEST-2", remediation_action_id="ACT-2", implementation_id="IMPL-2"
    )
    retest = SimpleNamespace(
        root_cause_analysis_id="RCA-2", review_decision_id=12, diagnosis_id="DIAG-2",
        remediation_action_id="ACT-2", implementation_id="IMPL-2", test_execution_id="TEST-2",
    )
    patch = SimpleNamespace(root_cause_analysis_id="RCA-OLD", remediation_action_id="ACT-2")

    class Db:
        bind = None

        def __init__(self):
            self.values = iter([None, None, review, diagnosis, action, implementation, test, retest, patch])

        def scalar(self, _statement):
            return next(self.values)

    monkeypatch.setattr(
        workflow_provenance_service.root_cause_analysis_service,
        "get_current_analysis",
        lambda db, incident_id: current,
    )
    chain = workflow_provenance_service.get_exact_report_chain(Db(), "INC-1")
    assert chain["action"] is action
    assert chain["controlled_retest"] is retest
    assert chain["patch"] is None
