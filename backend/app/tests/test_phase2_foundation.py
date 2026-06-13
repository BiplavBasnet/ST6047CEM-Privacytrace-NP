"""
Phase 2 foundation tests: models, relationships, constraints, seed, health.

Scope: database layer only. No ingestion, detection services, causality, LLM, or frontend.
"""

from datetime import datetime, timezone
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from app.database import Base, SessionLocal, check_database_connection, engine
from app.db.seed_phase2 import SEED_INCIDENT_ID, seed_phase2
from app.main import app
from app.tests.route_test_utils import registered_routes
from app.models import (
    AccessEvent,
    AIRemediationSuggestion,
    AuditLog,
    DeploymentEvent,
    DependencyRisk,
    Detection,
    EvaluationMetric,
    EvidenceFile,
    FixVerification,
    Incident,
    IntegrationToken,
    LlmReport,
    NormalizedEvent,
    PrivacyAlert,
    Report,
    RemediationAction,
    ReviewDecision,
    ReviewDraft,
    RootCauseScore,
    SastFinding,
    SecretFinding,
    User,
    CicdEvidence,
    AffectedSubjectReference,
    BreachAlert,
    ContainmentAction,
    CustomerNotificationDecision,
    DeliveryAttempt,
    NotificationOutbox,
    PrivacyHarm,
    PrivacyImpactAssessment,
    PrivacyImpactFactor,
)
from app.models.enums import (
    EvidenceType,
    IncidentStatus,
    Severity,
    UserRole,
    VerificationStatus,
)

# ---------------------------------------------------------------------------
# 1. Application health
# ---------------------------------------------------------------------------


def test_fastapi_app_imports():
    assert app.title == "PrivacyTrace-NP"
    assert app.version == "0.1.0"


@pytest.mark.integration
def test_health_endpoint_success_with_live_db(client: TestClient, migrated_db):
    if not check_database_connection():
        pytest.skip("PostgreSQL is not running")

    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"


# ---------------------------------------------------------------------------
# 2. Database configuration
# ---------------------------------------------------------------------------


def test_database_settings_and_engine():
    from app.config import get_settings

    settings = get_settings()
    assert settings.database_url.startswith("postgresql://")
    assert str(engine.url).startswith("postgresql")
    if os.getenv("REQUIRE_TEST_POSTGRES") == "1":
        from app.tests.conftest import _require_dedicated_test_postgres

        _require_dedicated_test_postgres()


@pytest.mark.integration
def test_database_tables_create_without_error(migrated_db):
    inspector = inspect(engine)
    assert set(Base.metadata.tables).issubset(set(inspector.get_table_names()))


# ---------------------------------------------------------------------------
# 3. Model imports
# ---------------------------------------------------------------------------


def test_all_phase2_models_import():
    models = [
        User,
        AIRemediationSuggestion,
        EvidenceFile,
        NormalizedEvent,
        PrivacyAlert,
        Incident,
        Detection,
        SastFinding,
        SecretFinding,
        DeploymentEvent,
        AccessEvent,
        DependencyRisk,
        RootCauseScore,
        ReviewDecision,
        FixVerification,
        AuditLog,
        LlmReport,
        Report,
        EvaluationMetric,
        IntegrationToken,
        ReviewDraft,
        RemediationAction,
        CicdEvidence,
        AffectedSubjectReference,
        BreachAlert,
        ContainmentAction,
        CustomerNotificationDecision,
        DeliveryAttempt,
        NotificationOutbox,
        PrivacyHarm,
        PrivacyImpactAssessment,
        PrivacyImpactFactor,
    ]
    for model in models:
        assert model.__tablename__
    required_tables = {model.__tablename__ for model in models}
    assert required_tables.issubset(set(Base.metadata.tables))


# ---------------------------------------------------------------------------
# 4. User model
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_user_model_create_and_constraints(db_session):
    admin = User(name="Admin", email="admin-test@example.com", role=UserRole.ADMIN)
    developer = User(
        name="Developer", email="developer-test@example.com", role=UserRole.DEVELOPER
    )
    analyst = User(
        name="Analyst",
        email="analyst-test@example.com",
        role=UserRole.SECURITY_ANALYST,
    )
    db_session.add_all([admin, developer, analyst])
    db_session.commit()

    saved = db_session.query(User).order_by(User.id).all()
    assert len(saved) == 3
    assert {u.role for u in saved} == {
        UserRole.ADMIN,
        UserRole.DEVELOPER,
        UserRole.SECURITY_ANALYST,
    }
    assert all(u.created_at is not None for u in saved)
    assert len({u.email for u in saved}) == 3


# ---------------------------------------------------------------------------
# 5. Incident model
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_incident_model_create(db_session):
    incident = Incident(
        incident_id="INC-001",
        title="Sensitive data exposure in wallet transfer logs",
        affected_endpoint="/wallet/transfer",
        affected_service="wallet-service",
        status=IncidentStatus.NEW,
        severity=Severity.HIGH,
    )
    db_session.add(incident)
    db_session.commit()

    saved = db_session.query(Incident).filter_by(incident_id="INC-001").one()
    assert saved.title == "Sensitive data exposure in wallet transfer logs"
    assert saved.affected_endpoint == "/wallet/transfer"
    assert saved.status == IncidentStatus.NEW
    assert saved.created_at is not None
    assert saved.updated_at is not None


# ---------------------------------------------------------------------------
# 6. Evidence relationships
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_evidence_linked_to_incident(db_session):
    db_session.add(
        Incident(
            incident_id="INC-001",
            title="Sensitive data exposure in wallet transfer logs",
            affected_endpoint="/wallet/transfer",
            affected_service="wallet-service",
            status=IncidentStatus.NEW,
            severity=Severity.HIGH,
        )
    )
    db_session.flush()

    db_session.add_all(
        [
            EvidenceFile(
                evidence_id="LOG-001",
                file_name="wallet_api.log",
                evidence_type=EvidenceType.API_LOG,
                source_system="wallet-service",
                linked_incident_id="INC-001",
            ),
            EvidenceFile(
                evidence_id="DEPLOY-001",
                file_name="deploy.log",
                evidence_type=EvidenceType.DEPLOYMENT_LOG,
                source_system="ci_cd_pipeline",
                linked_incident_id="INC-001",
            ),
        ]
    )
    db_session.commit()

    incident = (
        db_session.query(Incident)
        .options(selectinload(Incident.evidence_files))
        .filter_by(incident_id="INC-001")
        .one()
    )
    assert len(incident.evidence_files) == 2
    evidence_ids = {e.evidence_id for e in incident.evidence_files}
    assert evidence_ids == {"LOG-001", "DEPLOY-001"}


# ---------------------------------------------------------------------------
# 7. Normalized event relationships
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_normalized_event_relationships(db_session):
    _seed_incident_and_evidence(db_session)

    event = NormalizedEvent(
        event_id="EVT-001",
        evidence_id="LOG-001",
        timestamp=datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc),
        source_type="api_log",
        service_name="wallet-service",
        endpoint="/wallet/transfer",
        masked_message="Transfer request with masked phone 984****567",
        linked_incident_id="INC-001",
    )
    db_session.add(event)
    db_session.commit()

    saved = db_session.query(NormalizedEvent).filter_by(event_id="EVT-001").one()
    assert saved.masked_message is not None
    assert saved.endpoint == "/wallet/transfer"

    evidence = (
        db_session.query(EvidenceFile)
        .options(selectinload(EvidenceFile.normalized_events))
        .filter_by(evidence_id="LOG-001")
        .one()
    )
    assert len(evidence.normalized_events) == 1
    assert evidence.normalized_events[0].event_id == "EVT-001"

    incident = (
        db_session.query(Incident)
        .options(selectinload(Incident.normalized_events))
        .filter_by(incident_id="INC-001")
        .one()
    )
    assert len(incident.normalized_events) == 1


# ---------------------------------------------------------------------------
# 8. Detection relationships
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_detection_relationships_masked_only(db_session):
    _seed_incident_and_evidence(db_session)

    detection = Detection(
        detection_id="DET-001",
        incident_id="INC-001",
        evidence_id="LOG-001",
        sensitive_type="nepali_phone_number",
        masked_value="984****567",
        confidence=0.95,
        severity=Severity.HIGH,
        detector_name="regex_detector",
    )
    db_session.add(detection)
    db_session.commit()

    saved = db_session.query(Detection).filter_by(detection_id="DET-001").one()
    assert saved.masked_value == "984****567"
    assert saved.incident_id == "INC-001"
    assert saved.evidence_id == "LOG-001"
    assert not hasattr(saved, "raw_value")
    columns = {c.name for c in Detection.__table__.columns}
    assert "raw_value" not in columns
    assert "masked_value" in columns


# ---------------------------------------------------------------------------
# 9. Root-cause score
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_root_cause_score_json_fields(db_session):
    _seed_incident_and_evidence(db_session)

    score = RootCauseScore(
        root_cause_id="RCA-TEST-001",
        incident_id="INC-001",
        cause_name="unsafe_request_body_logging",
        likely_root_cause="unsafe_request_body_logging",
        confidence=0.88,
        confidence_band="high",
        rank=1,
        supporting_evidence_ids=["LOG-001", "DEPLOY-001"],
        missing_evidence=["Missing code scan finding"],
        human_review_required=True,
    )
    db_session.add(score)
    db_session.commit()

    saved = db_session.query(RootCauseScore).filter_by(incident_id="INC-001").one()
    assert saved.supporting_evidence_ids == ["LOG-001", "DEPLOY-001"]
    assert saved.missing_evidence == ["Missing code scan finding"]
    assert saved.incident.incident_id == "INC-001"


# ---------------------------------------------------------------------------
# 10. Review, audit, fix verification
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_review_audit_fix_verification(db_session):
    admin = User(name="Admin", email="reviewer@example.com", role=UserRole.ADMIN)
    db_session.add(admin)
    _seed_incident_and_evidence(db_session)
    db_session.flush()

    review = ReviewDecision(
        incident_id="INC-001",
        reviewer_id=admin.id,
        decision="needs_more_evidence",
        comment="Synthetic review for Phase 2 test.",
    )
    db_session.add(review)
    db_session.flush()

    audit = AuditLog(
        actor_id=admin.id,
        action="review_decision_recorded",
        target_type="incident",
        target_id="INC-001",
        details={"decision": "needs_more_evidence"},
    )
    fix = FixVerification(
        incident_id="INC-001",
        verification_status=VerificationStatus.INCONCLUSIVE,
        checks_run=["rescan_logs"],
        passed_checks=[],
        failed_checks=[],
        evidence_used=["LOG-001"],
    )
    db_session.add_all([audit, fix])
    db_session.commit()

    saved_review = db_session.query(ReviewDecision).one()
    assert saved_review.incident_id == "INC-001"
    assert saved_review.reviewer_id == admin.id

    saved_audit = db_session.query(AuditLog).one()
    assert saved_audit.action == "review_decision_recorded"

    saved_fix = db_session.query(FixVerification).one()
    assert saved_fix.verification_status == VerificationStatus.INCONCLUSIVE
    assert saved_fix.incident_id == "INC-001"


# ---------------------------------------------------------------------------
# 11. Unique constraints
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_unique_constraint_users_email(db_session):
    db_session.add(User(name="A", email="dup@example.com", role=UserRole.VIEWER))
    db_session.commit()
    db_session.add(User(name="B", email="dup@example.com", role=UserRole.VIEWER))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.integration
def test_unique_constraint_evidence_id(db_session):
    _seed_incident_and_evidence(db_session)
    db_session.add(
        EvidenceFile(
            evidence_id="LOG-001",
            file_name="duplicate.log",
            evidence_type=EvidenceType.API_LOG,
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.integration
def test_unique_constraint_event_id(db_session):
    _seed_incident_and_evidence(db_session)
    ts = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)
    db_session.add(
        NormalizedEvent(
            event_id="EVT-DUP",
            evidence_id="LOG-001",
            timestamp=ts,
            source_type="api_log",
        )
    )
    db_session.commit()
    db_session.add(
        NormalizedEvent(
            event_id="EVT-DUP",
            evidence_id="LOG-001",
            timestamp=ts,
            source_type="api_log",
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.integration
def test_unique_constraint_incident_id(db_session):
    db_session.add(
        Incident(
            incident_id="INC-DUP",
            title="First",
            status=IncidentStatus.NEW,
            severity=Severity.LOW,
        )
    )
    db_session.commit()
    db_session.add(
        Incident(
            incident_id="INC-DUP",
            title="Second",
            status=IncidentStatus.NEW,
            severity=Severity.LOW,
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.integration
def test_unique_constraint_detection_id(db_session):
    _seed_incident_and_evidence(db_session)
    db_session.add(
        Detection(
            detection_id="DET-DUP",
            incident_id="INC-001",
            sensitive_type="test",
            masked_value="***",
        )
    )
    db_session.commit()
    db_session.add(
        Detection(
            detection_id="DET-DUP",
            incident_id="INC-001",
            sensitive_type="test",
            masked_value="***",
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# ---------------------------------------------------------------------------
# 12. Seed script
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_seed_script_creates_expected_records(migrated_db):
    seed_phase2()

    db = SessionLocal()
    try:
        users = db.query(User).all()
        assert len(users) >= 3
        emails = {u.email for u in users}
        assert "admin@example.com" in emails
        assert "developer@example.com" in emails
        assert "analyst@example.com" in emails

        incident = db.query(Incident).filter_by(incident_id=SEED_INCIDENT_ID).one()
        assert incident is not None

        evidence = db.query(EvidenceFile).filter_by(linked_incident_id=SEED_INCIDENT_ID).all()
        assert len(evidence) == 2
    finally:
        db.close()

    seed_phase2()


# ---------------------------------------------------------------------------
# 13. Regression — no abandoned Phase 3 stub route prefixes
# ---------------------------------------------------------------------------


def test_no_legacy_phase3_stub_route_prefixes():
    routes = [r.path for r in registered_routes(app) if hasattr(r, "methods")]
    api_paths = [
        p
        for p in routes
        if p not in ("/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc")
    ]
    assert "/health" in api_paths
    # Early design stubs never implemented; real pipeline uses /evidence and /incidents.
    assert not any(
        p.startswith(prefix)
        for p in api_paths
        for prefix in ("/ingest", "/detect", "/causality")
    )


@pytest.mark.integration
def test_health_regression_after_db_tests(client: TestClient, migrated_db):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["database"] == "connected"


def _seed_incident_and_evidence(db_session) -> None:
    """Helper: INC-001 with LOG-001 and DEPLOY-001 evidence."""
    if db_session.query(Incident).filter_by(incident_id="INC-001").first() is None:
        db_session.add(
            Incident(
                incident_id="INC-001",
                title="Sensitive data exposure in wallet transfer logs",
                affected_endpoint="/wallet/transfer",
                affected_service="wallet-service",
                status=IncidentStatus.NEW,
                severity=Severity.HIGH,
            )
        )
        db_session.flush()

    if db_session.query(EvidenceFile).filter_by(evidence_id="LOG-001").first() is None:
        db_session.add_all(
            [
                EvidenceFile(
                    evidence_id="LOG-001",
                    file_name="wallet_api.log",
                    evidence_type=EvidenceType.API_LOG,
                    source_system="wallet-service",
                    linked_incident_id="INC-001",
                ),
                EvidenceFile(
                    evidence_id="DEPLOY-001",
                    file_name="deploy.log",
                    evidence_type=EvidenceType.DEPLOYMENT_LOG,
                    source_system="ci_cd_pipeline",
                    linked_incident_id="INC-001",
                ),
            ]
        )
        db_session.flush()

