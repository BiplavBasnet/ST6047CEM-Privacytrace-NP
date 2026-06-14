import pytest
from sqlalchemy import inspect

from app.database import engine

pytestmark = pytest.mark.usefixtures("migrated_db")


def test_report_exact_chain_schema_matches_migration_030():
    columns = {column["name"] for column in inspect(engine).get_columns("reports")}
    assert {
        "root_cause_analysis_version",
        "review_decision_id",
        "implementation_id",
        "controlled_retest_id",
        "fix_verification_id",
        "taxonomy_version",
        "exposure_policy_version",
        "recommendation_policy_version",
        "workflow_chain_status",
    } <= columns
    fks = inspect(engine).get_foreign_keys("reports")
    referred_by_local = {
        column: fk["referred_table"]
        for fk in fks
        for column in fk.get("constrained_columns") or []
    }
    assert referred_by_local.get("root_cause_analysis_id") == "root_cause_analyses"
    assert referred_by_local.get("review_decision_id") == "review_decisions"
    assert referred_by_local.get("remediation_diagnosis_id") == "remediation_diagnoses"
    assert referred_by_local.get("remediation_action_id") == "remediation_actions"
    assert referred_by_local.get("implementation_id") == "remediation_implementation_records"
    assert referred_by_local.get("patch_proposal_id") == "patch_proposals"
    assert referred_by_local.get("test_execution_id") == "remediation_test_executions"
    assert referred_by_local.get("controlled_retest_id") == "controlled_retests"
    assert referred_by_local.get("fix_verification_id") == "fix_verifications"
    assert referred_by_local.get("verification_outcome_id") == "verification_outcomes"
