from __future__ import annotations

from app.config import get_settings
from app.models import Detection, EvidenceFile, Incident, RootCauseScore, User
from app.models.enums import EvidenceType, IncidentStatus, ParsingStatus, Severity, UserRole
from app.services import root_cause_analysis_service
from app.tests.auth_test_utils import login

ROLE_CREDS = {
    "admin": ("admin@privacytrace.local", "AdminPass123!"),
    "security_analyst": ("analyst@privacytrace.local", "AnalystPass123!"),
    "devsecops_engineer": ("devsecops@privacytrace.local", "DevSecOpsPass123!"),
    "auditor": ("auditor@privacytrace.local", "AuditorPass123!"),
    "viewer": ("viewer@privacytrace.local", "ViewerPass123!"),
    "developer": ("developer@privacytrace.local", "DeveloperPass123!"),
}


def enable_mock_ai(monkeypatch, *, enabled: bool = True) -> None:
    monkeypatch.setenv("AI_ASSISTANT_ENABLED", "true" if enabled else "false")
    monkeypatch.setenv("AI_PROVIDER", "mock")
    monkeypatch.setenv("AI_MODEL", "mock-remediation")
    monkeypatch.setenv("AI_BASE_URL", "")
    monkeypatch.setenv("AI_API_KEY", "")
    get_settings.cache_clear()


def clear_ai_settings(monkeypatch) -> None:
    # Env vars beat Settings.env_file=".env"; pin code defaults so a local
    # AI_ASSISTANT_ENABLED=true does not leak into tests.
    monkeypatch.setenv("AI_ASSISTANT_ENABLED", "false")
    monkeypatch.setenv("AI_PROVIDER", "openai_compatible")
    monkeypatch.setenv("AI_MODEL", "")
    monkeypatch.setenv("AI_MODEL_CANDIDATES", "")
    monkeypatch.setenv("AI_BASE_URL", "")
    monkeypatch.setenv("AI_API_KEY", "")
    monkeypatch.setenv("AI_BACKUP_API_KEYS", "")
    get_settings.cache_clear()


def role_token(client, db_session, role: str = "security_analyst") -> str:
    db_session.commit()
    email, password = ROLE_CREDS[role]
    return login(client, email=email, password=password)


def seed_active_analyst(db_session) -> User:
    from sqlalchemy import select

    existing = db_session.scalar(
        select(User).where(User.email == "analyst-provenance@privacytrace.test")
    )
    if existing is not None:
        return existing
    user = User(
        name="Provenance Analyst",
        email="analyst-provenance@privacytrace.test",
        role=UserRole.SECURITY_ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()
    return user


def seed_ai_incident(
    db_session,
    *,
    incident_id: str = "INC-AI-001",
    unsafe_nested: bool = False,
) -> str:
    incident = Incident(
        incident_id=incident_id,
        title="Masked privacy exposure in wallet service",
        affected_endpoint="/api/v1/wallet/transfer",
        affected_service="wallet-service",
        status=IncidentStatus.NEW,
        severity=Severity.HIGH,
        summary="Masked evidence indicates sensitive data may have reached application logs.",
    )
    evidence = EvidenceFile(
        evidence_id=f"EVD-{incident_id[-3:]}",
        file_name="masked-wallet-log.json",
        evidence_type=EvidenceType.API_LOG,
        source_system="wallet-service",
        file_hash="sha256:masked-ai-evidence",
        parsing_status=ParsingStatus.PARSED,
        linked_incident_id=incident_id,
    )
    detection = Detection(
        detection_id=f"DET-{incident_id[-3:]}",
        incident_id=incident_id,
        evidence_id=evidence.evidence_id,
        sensitive_type="nepal_phone",
        raw_value_hash="sha256:phone-hash-only",
        masked_value="984****567",
        confidence=0.94,
        severity=Severity.HIGH,
        detector_name="privacytrace-test-detector",
    )
    score = RootCauseScore(
        root_cause_id=f"RC-{incident_id[-3:]}",
        incident_id=incident_id,
        cause_name="logging_redaction_gap",
        likely_root_cause="logging_redaction_gap",
        confidence=0.72,
        confidence_band="medium",
        rank=1,
        supporting_evidence_ids=[evidence.evidence_id],
        missing_evidence=["retest_log_after_redaction_change"],
        score_breakdown=[
            {
                "signal": "masked detection in application log",
                "raw_fragment": "phone 9841234567" if unsafe_nested else "masked value only",
            }
        ],
        matched_signals=[{"signal": "masked_nepal_phone_detection", "weight": 0.7}],
        negative_signals=[],
        correlation_reasons=["masked detection linked to wallet endpoint"],
        contradicting_evidence=[],
        evidence_roles=[{"evidence_id": evidence.evidence_id, "role": "supporting"}],
        suggested_actions=[{"action": "review logging middleware"}],
        recommended_fix="Review wallet-service logging middleware and update redaction before log emission.",
        human_review_required=True,
        analysis_id=f"RCA-SEED-{incident_id[-12:]}",
        analysis_version=1,
        evidence_snapshot_hash=f"seed-snapshot-{incident_id}",
    )
    db_session.add_all([incident, evidence, detection, score])
    db_session.flush()
    root_cause_analysis_service.ensure_seed_analysis_for_incident(
        db_session,
        incident_id,
        analysis_id=score.analysis_id,
        evidence_snapshot_hash=score.evidence_snapshot_hash or f"seed-snapshot-{incident_id}",
        analysis_version=1,
    )
    return incident_id
