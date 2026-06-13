"""Phase 2 tests: models, migrations, seed data, relationships."""

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from app.database import Base, engine
from app.db.seed_phase2 import SEED_INCIDENT_ID
from app.models import EvidenceFile, Incident, User

EXPECTED_TABLES = {
    "users",
    "evidence_files",
    "normalized_events",
    "incidents",
    "detections",
    "sast_findings",
    "secret_findings",
    "deployment_events",
    "access_events",
    "dependency_risks",
    "root_cause_scores",
    "review_decisions",
    "fix_verifications",
    "audit_logs",
    "reports",
    "evaluation_metrics",
    "llm_reports",
    "scanner_evidence_records",
    "privacy_alerts",
    "ai_remediation_suggestions",
    "integration_tokens",
    "review_drafts",
    "remediation_actions",
    "cicd_evidence",
    "privacy_impact_assessments",
    "privacy_impact_factors",
    "privacy_harms",
    "affected_subject_references",
    "breach_alerts",
    "containment_actions",
    "customer_notification_decisions",
    "notification_outbox",
    "delivery_attempts",
    "organisations",
    "organisation_memberships",
    "organisation_invitations",
    "deployment_setup",
    "organisation_domain_challenges",
    "organisation_email_verifications",
    "organisation_manual_reviews",
}


def test_all_models_import():
    """All Phase 2 model classes import and register metadata."""
    assert EXPECTED_TABLES.issubset(set(Base.metadata.tables))


def test_unique_constraints_defined():
    """Business keys and email have unique constraints."""
    users = Base.metadata.tables["users"]
    evidence = Base.metadata.tables["evidence_files"]
    events = Base.metadata.tables["normalized_events"]
    incidents = Base.metadata.tables["incidents"]
    detections = Base.metadata.tables["detections"]

    assert users.c.email.unique is True
    assert evidence.c.evidence_id.unique is True
    assert events.c.event_id.unique is True
    assert incidents.c.incident_id.unique is True
    assert detections.c.detection_id.unique is True


@pytest.mark.integration
def test_tables_created_via_migration(migrated_db):
    # A plain drop_all only removes tables; the migration-only trigger
    # functions that `migrated_db` applies (from 015/018) would still be
    # present and collide with migration 015's non-idempotent CREATE FUNCTION
    # statements. Reset the whole schema so this test replays every
    # migration against a genuinely empty database.
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))

    backend_root = Path(__file__).resolve().parents[2]
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "alembic"))
    command.upgrade(config, "head")

    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    assert EXPECTED_TABLES.issubset(table_names)
    with engine.connect() as connection:
        revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    assert revision == "037_connector_client_event_id"


@pytest.mark.integration
def test_sample_users_inserted(seeded_db):
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        users = db.query(User).all()
        assert len(users) >= 3
        emails = {u.email for u in users}
        assert "admin@example.com" in emails
        assert "developer@example.com" in emails
        assert "analyst@example.com" in emails
    finally:
        db.close()


@pytest.mark.integration
def test_sample_incident_inserted(seeded_db):
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        incident = db.query(Incident).filter_by(incident_id=SEED_INCIDENT_ID).one()
        assert incident.title
        assert incident.affected_endpoint == "/api/v1/wallet/transfer"
    finally:
        db.close()


@pytest.mark.integration
def test_evidence_links_to_incident(seeded_db):
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        evidence = db.query(EvidenceFile).filter_by(linked_incident_id=SEED_INCIDENT_ID).all()
        assert len(evidence) == 2
        evidence_ids = {e.evidence_id for e in evidence}
        assert "EVD-SEED-API-001" in evidence_ids
        assert "EVD-SEED-SAST-001" in evidence_ids
    finally:
        db.close()


@pytest.mark.integration
def test_incident_retrieves_linked_evidence(seeded_db):
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        incident = (
            db.query(Incident)
            .options(selectinload(Incident.evidence_files))
            .filter_by(incident_id=SEED_INCIDENT_ID)
            .one()
        )
        assert len(incident.evidence_files) == 2
        assert all(e.linked_incident_id == SEED_INCIDENT_ID for e in incident.evidence_files)
    finally:
        db.close()


@pytest.mark.integration
def test_duplicate_email_raises(migrated_db):
    from app.database import SessionLocal

    from app.models.enums import UserRole

    db = SessionLocal()
    try:
        db.add(
            User(name="A", email="dup@example.com", role=UserRole.VIEWER)
        )
        db.commit()
        db.add(
            User(name="B", email="dup@example.com", role=UserRole.VIEWER)
        )
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
    finally:
        db.close()


@pytest.mark.integration
def test_health_still_works(client: TestClient, migrated_db):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
