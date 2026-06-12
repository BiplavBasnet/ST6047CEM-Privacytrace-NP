import pytest
from alembic import command
from alembic.config import Config
from pathlib import Path
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from app.database import engine
from app.tests.conftest import _require_dedicated_test_postgres, _reset_test_schema


@pytest.fixture(scope="module", autouse=True)
def alembic_upgraded_db():
    _require_dedicated_test_postgres()
    _reset_test_schema()
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    config.set_main_option("script_location", str(Path(__file__).resolve().parents[2] / "alembic"))
    command.upgrade(config, "head")
    yield
    _reset_test_schema()


def test_migration_031_security_constraints_exist():
    inspector = inspect(engine)
    retest_columns = {column["name"] for column in inspector.get_columns("controlled_retests")}
    assert {"required_dimensions", "missing_dimensions"} <= retest_columns
    report_fk = next(
        fk for fk in inspector.get_foreign_keys("reports") if fk["referred_table"] == "incidents"
    )
    assert report_fk["options"].get("ondelete") == "RESTRICT"
    expected = {
        "review_decisions": {"fk031_review_rca_incident"},
        "remediation_actions": {
            "fk031_action_rca_incident", "fk031_action_review_incident",
            "fk031_action_diagnosis_incident",
        },
        "remediation_implementation_records": {
            "fk031_impl_rca_incident", "fk031_impl_review_incident",
            "fk031_impl_diagnosis_incident", "fk031_impl_action_incident",
        },
        "remediation_test_executions": {
            "fk031_test_action_incident", "fk031_test_impl_incident",
            "fk031_test_patch_incident",
        },
        "controlled_retests": {
            "fk031_retest_rca_incident", "fk031_retest_review_incident",
            "fk031_retest_diagnosis_incident", "fk031_retest_action_incident",
            "fk031_retest_impl_incident", "fk031_retest_test_incident",
        },
        "verification_outcomes": {
            "fk031_outcome_rca_incident", "fk031_outcome_review_incident",
            "fk031_outcome_diagnosis_incident", "fk031_outcome_action_incident",
            "fk031_outcome_impl_incident", "fk031_outcome_test_incident",
            "fk031_outcome_retest_incident", "fk031_outcome_fix_incident",
        },
        "reports": {"fk031_report_rca_anchor", "fk031_report_outcome_incident"},
    }
    for table, names in expected.items():
        assert names <= {fk["name"] for fk in inspector.get_foreign_keys(table)}


def test_migration_031_rejects_cross_incident_review_rca():
    with engine.connect() as connection:
        transaction = connection.begin()
        connection.execute(text("INSERT INTO incidents (incident_id,title,status,severity) VALUES ('INC-031-A','A','new','medium'),('INC-031-B','B','new','medium')"))
        connection.execute(text("INSERT INTO root_cause_analyses (analysis_id,incident_id,analysis_version,evidence_snapshot_hash,evidence_revision,stale,current) VALUES ('RCA-031-A','INC-031-A',1,'snapshot',1,false,true)"))
        with pytest.raises(IntegrityError):
            connection.execute(text("INSERT INTO review_decisions (incident_id,decision,evidence_checklist,evidence_relied_on,missing_evidence_acknowledged,root_cause_analysis_id,limitations_acknowledged,progression_valid) VALUES ('INC-031-B','approved','[]','[]',false,'RCA-031-A',false,true)"))
        transaction.rollback()
