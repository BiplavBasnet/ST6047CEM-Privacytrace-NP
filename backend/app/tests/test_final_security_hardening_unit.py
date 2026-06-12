import inspect
import importlib.util
from pathlib import Path

from app.services import (
    ai_remediation_service,
    audit_service,
    fix_verification_gate_service,
    llm_investigation_service,
    remediation_lifecycle_service,
    report_service,
)


def test_controlled_retest_requires_complete_explicit_dimension_contract():
    lifecycle = inspect.getsource(remediation_lifecycle_service.record_controlled_retest)
    gate = inspect.getsource(fix_verification_gate_service.assert_fix_verification_allowed)
    for dimension in (
        "service_name", "endpoint", "sensitive_type", "exposure_location", "component"
    ):
        assert dimension in lifecycle
        assert dimension in gate
    assert "missing_dimensions" in lifecycle
    assert "set(retest.required_dimensions or []) != required_contract" in gate


def test_encrypted_audit_and_reports_do_not_keep_plaintext():
    assert "entry.details = None" in inspect.getsource(audit_service.log_action)
    assert "record.content_json = None" in inspect.getsource(report_service.generate_report)
    assert "resolve_audit_details(row)" in inspect.getsource(audit_service.list_audit_logs)


def test_blocked_llm_input_uses_central_audit_service():
    source = inspect.getsource(llm_investigation_service._log_blocked_input)
    assert "audit_service.log_action" in source
    assert "AuditLog(" not in source


def test_legacy_ai_acceptance_is_advisory_only():
    source = inspect.getsource(ai_remediation_service.accept_suggestion)
    assert "row.accepted_as_remediation_action_id = None" in source
    assert 'row.status = "converted_to_remediation_action"' not in source


def test_ordinary_report_uses_exact_chain_and_omits_unbound_llm():
    source = inspect.getsource(report_service.build_incident_report_content)
    assert "get_exact_report_chain" in source
    assert '"llm_explanation_summary": None' in source


def test_migration_031_fk_targets_and_downgrade_are_symmetric():
    path = Path(__file__).resolve().parents[2] / "alembic" / "versions" / "031_security_ownership_hardening.py"
    spec = importlib.util.spec_from_file_location("migration_031", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    unique_targets = {(table, columns) for _, table, columns in migration.UNIQUE_INDEXES}
    assert all((parent, remote) in unique_targets for _, _, _, parent, remote in migration.COMPOSITE_FKS)
    assert all(child != parent for _, child, _, parent, _ in migration.COMPOSITE_FKS)
    source = inspect.getsource(migration.downgrade)
    assert "reversed(COMPOSITE_FKS)" in source
    assert "reversed(UNIQUE_INDEXES)" in source
    assert 'ondelete="CASCADE"' in source
