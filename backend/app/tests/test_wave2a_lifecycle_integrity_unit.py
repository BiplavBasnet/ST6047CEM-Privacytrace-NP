"""Database-independent checks for the Wave 2A schema contract."""

from app.models.remediation_action import RemediationAction
from app.models.root_cause_analysis import RootCauseAnalysis


def test_current_rca_and_version_are_unique_in_model_metadata():
    index_names = {index.name for index in RootCauseAnalysis.__table__.indexes}
    constraint_names = {
        constraint.name for constraint in RootCauseAnalysis.__table__.constraints
    }
    assert "uq_root_cause_current_incident" in index_names
    assert "uq_root_cause_incident_version" in constraint_names


def test_diagnosis_has_one_canonical_action_in_model_metadata():
    indexes = {
        index.name: index for index in RemediationAction.__table__.indexes
    }
    canonical = indexes["uq_remediation_actions_diagnosis"]
    assert canonical.unique is True
    assert [column.name for column in canonical.columns] == ["diagnosis_id"]


def test_historical_action_invalidation_fields_are_persisted():
    columns = RemediationAction.__table__.columns
    assert "workflow_status" in columns
    assert "invalidation_reason" in columns
