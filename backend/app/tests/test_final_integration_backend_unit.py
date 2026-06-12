import inspect

from app.models.remediation_diagnosis import RemediationDiagnosis
from app.schemas.problem_specific_remediation_schema import CurrentRemediationDiagnosisRead
from app.services import (
    ai_remediation_diagnosis_service,
    live_monitor_service,
    remediation_lifecycle_service,
    report_readiness_service,
    workflow_provenance_service,
)


def test_current_diagnosis_branch_has_database_uniqueness():
    assert "uq_remediation_diagnosis_current_branch" in {
        item.name for item in RemediationDiagnosis.__table__.indexes
    }


def test_diagnosis_generation_locks_and_supersedes_branch():
    source = inspect.getsource(ai_remediation_diagnosis_service.generate_problem_specific_remediation)
    assert "with_for_update" in source
    assert 'workflow_status="superseded"' in source
    assert "eligible_for_learning=False" in source


def test_manual_implementation_identity_includes_summary_and_evidence():
    source = inspect.getsource(remediation_lifecycle_service.record_implementation)
    assert 'change_hash or ""' in source
    assert 'safe_reference or ""' in source
    assert "safe_summary" in source
    assert "with_for_update" in source


def test_alert_linking_locks_before_recheck():
    source = inspect.getsource(live_monitor_service.create_or_link_incident)
    assert "with_for_update" in source
    assert source.index("with_for_update") < source.index("if alert.linked_incident_id")


def test_readiness_uses_persisted_exact_lifecycle():
    source = inspect.getsource(report_readiness_service.get_report_readiness)
    assert 'provenance.get("implementation_status") == "completed"' in source
    assert 'provenance.get("test_execution_status") == "passed"' in source
    assert 'provenance.get("controlled_retest_status") == "completed"' in source
    assert "VerificationStatus.PASSED.value" in source
    assert 'provenance.get("verification_outcome") is not None' not in source
    assert "facts.retest_evidence_count > 0" not in source


def test_exact_false_positive_is_terminal_without_remediation(monkeypatch):
    from types import SimpleNamespace

    current = SimpleNamespace(
        analysis_id="RCA-1", analysis_version=1, evidence_snapshot_hash="snap",
        stale=False, current=True,
    )
    review = SimpleNamespace(
        id=1, incident_id="INC-1", root_cause_analysis_id="RCA-1",
        root_cause_analysis_version=1, evidence_snapshot_hash="snap",
        decision="rejected_false_positive", progression_valid=True,
    )

    class Db:
        bind = None

        def __init__(self):
            self.values = iter([None, None, review])

        def scalar(self, _statement):
            return next(self.values)

    monkeypatch.setattr(
        workflow_provenance_service.root_cause_analysis_service,
        "get_current_analysis", lambda db, incident_id: current,
    )
    chain = workflow_provenance_service.get_exact_report_chain(Db(), "INC-1")
    assert chain["workflow_chain_status"] == "current_false_positive"
    assert chain["review"] is review
    assert chain["diagnosis"] is None
    assert chain["outcome"] is None


def test_current_diagnosis_read_has_safe_panel_source_fields():
    required = {
        "technical_mechanism", "affected_service", "affected_endpoint",
        "affected_component", "affected_file", "affected_function",
        "affected_configuration", "exact_source_location_known", "supporting_evidence_ids",
        "contradicting_evidence_ids", "missing_evidence", "limitations",
        "primary_remediation", "alternative_remediations", "proposed_change",
        "generation_mode", "playbook_id", "playbook_version", "model_provider",
        "model_name", "prompt_template_version", "recommendation_policy_version",
    }
    assert required <= set(CurrentRemediationDiagnosisRead.model_fields)
    assert "original_ai_payload" not in CurrentRemediationDiagnosisRead.model_fields
