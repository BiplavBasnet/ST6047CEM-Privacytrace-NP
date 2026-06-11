from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.affected_subject import AffectedSubjectReference
from app.models.breach_alert import BreachAlert
from app.models.containment_action import ContainmentAction
from app.models.detection import Detection
from app.models.enums import IncidentStatus
from app.models.incident import Incident
from app.models.privacy_impact import PrivacyImpactAssessment, PrivacyImpactFactor
from app.services import audit_safety_service, audit_service


class BreachAlertError(Exception):
    pass


class BreachAlertNotFoundError(BreachAlertError):
    pass


class BreachAlertStateError(BreachAlertError):
    pass


_TERMINAL = {"resolved", "false_positive", "cancelled"}
_CREDENTIAL_ACTIONS = {
    "authorization_header": "revoke_access_token", "jwt_token": "revoke_access_token",
    "bearer_token": "revoke_access_token", "access_token": "revoke_access_token",
    "session_token": "invalidate_sessions", "api_key": "rotate_api_key",
    "password": "force_password_reset", "private_key": "manual_action_required",
}


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"


def _dedupe_signature(assessment: PrivacyImpactAssessment) -> str:
    payload = {
        "incident": assessment.incident_id,
        "type": "customer_exposure",
        "categories": sorted(str(item) for item in assessment.data_categories or []),
        "credential": assessment.credential_exposure_present,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _dedupe_window(now: datetime, seconds: int) -> datetime:
    size = max(1, seconds)
    epoch = int(now.timestamp())
    return datetime.fromtimestamp(epoch - (epoch % size), tz=timezone.utc)


def _dedupe_key(signature: str, window_started_at: datetime) -> str:
    return hashlib.sha256(f"{signature}:{window_started_at.isoformat()}".encode("utf-8")).hexdigest()


def _lock_dedupe_signature(db: Session, signature: str) -> None:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"breach-alert:{signature}"})


def _factor_codes(db: Session, assessment_id: str) -> set[str]:
    return set(db.scalars(select(PrivacyImpactFactor.factor_code).where(PrivacyImpactFactor.assessment_id == assessment_id)).all())


def _alert_severity(db: Session, assessment: PrivacyImpactAssessment, affected_count: int | None) -> tuple[str, list[str]]:
    factors = _factor_codes(db, assessment.assessment_id)
    categories = set(assessment.data_categories or [])
    reasons: list[str] = []
    critical = False
    if "active_credential_exposure" in factors:
        critical = True; reasons.append("active_credential_exposure")
    if assessment.credential_exposure_present and assessment.public_exposure_present:
        critical = True; reasons.append("public_credential_exposure")
    if "financial_data" in categories and assessment.ease_of_identification_score >= 0.75:
        critical = True; reasons.append("identifiable_financial_data")
    if "confirmed_exfiltration" in factors:
        critical = True; reasons.append("confirmed_exfiltration")
    if assessment.malicious_intent_status == "confirmed":
        critical = True; reasons.append("confirmed_malicious_access")
    if assessment.breach_severity_level == "very_high":
        critical = True; reasons.append("very_high_breach_severity")
    if assessment.privacy_harm_level == "critical":
        critical = True; reasons.append("critical_privacy_harm")
    if (affected_count or 0) > 1 and assessment.external_access_confirmed:
        critical = True; reasons.append("multiple_subjects_external_access")
    if critical:
        return "critical", reasons
    if assessment.credential_exposure_present:
        reasons.append("credential_exposure_requires_review")
    if not reasons:
        reasons.append("customer_data_detected")
    if assessment.breach_severity_level == "high" or assessment.privacy_harm_level == "high" or assessment.credential_exposure_present:
        return "high", reasons
    if assessment.breach_severity_level == "medium" or assessment.privacy_harm_level == "medium":
        return "medium", reasons
    return "low", reasons


def _recommend_containment(db: Session, assessment: PrivacyImpactAssessment, *, actor_id: int | None) -> None:
    if not assessment.credential_exposure_present:
        return
    credential_types = sorted(set(db.scalars(select(Detection.sensitive_type).where(Detection.incident_id == assessment.incident_id, Detection.sensitive_type.in_(tuple(_CREDENTIAL_ACTIONS)))).all()))
    credential_types = credential_types or ["unknown_credential"]
    subject_ids = list(db.scalars(select(AffectedSubjectReference.subject_reference_id).where(AffectedSubjectReference.incident_id == assessment.incident_id)).all()) or [None]
    for credential_type in credential_types:
        action_type = _CREDENTIAL_ACTIONS.get(credential_type, "manual_action_required")
        for subject_id in subject_ids:
            exists = db.scalar(select(ContainmentAction.id).where(
                ContainmentAction.incident_id == assessment.incident_id,
                ContainmentAction.affected_subject_reference_id == subject_id,
                ContainmentAction.action_type == action_type,
                ContainmentAction.credential_type == credential_type,
            ).limit(1))
            if exists is not None:
                continue
            action = ContainmentAction(
                containment_action_id=_new_id("CTA"), incident_id=assessment.incident_id,
                affected_subject_reference_id=subject_id, action_type=action_type,
                credential_type=credential_type, status="recommended",
                reason="Credential exposure requires authorised containment review.", requires_approval=True,
            )
            db.add(action)
            db.flush()
            audit_service.log_action(db, action="credential_containment_recommended", actor_id=actor_id,
                target_type="containment_action", target_id=action.containment_action_id,
                details={"incident_id": assessment.incident_id, "action_type": action_type, "credential_type": credential_type,
                         "subject_reference_id": subject_id, "reason_code": "credential_exposure"})


def evaluate_assessment(db: Session, assessment: PrivacyImpactAssessment, *, actor_id: int | None = None) -> BreachAlert | None:
    settings = get_settings()
    if not settings.breach_alerts_enabled:
        return None
    incident = db.scalar(select(Incident).where(Incident.incident_id == assessment.incident_id))
    if incident is None:
        raise BreachAlertStateError("Incident is unavailable for breach-alert evaluation.")
    subject_count = int(db.scalar(select(func.count(AffectedSubjectReference.id)).where(AffectedSubjectReference.incident_id == assessment.incident_id)) or 0)
    affected_count = subject_count or assessment.affected_subject_count
    severity, reason_codes = _alert_severity(db, assessment, affected_count)
    observed_at = datetime.now(timezone.utc)
    signature = _dedupe_signature(assessment)
    window_started_at = _dedupe_window(observed_at, settings.breach_alert_deduplication_window_seconds)
    key = _dedupe_key(signature, window_started_at)
    _lock_dedupe_signature(db, signature)
    alert = db.scalar(
        select(BreachAlert).where(BreachAlert.deduplication_key == key).with_for_update()
    )
    verified_incident = incident.status in {IncidentStatus.CONFIRMED_INCIDENT, IncidentStatus.FIXED, IncidentStatus.CLOSED}
    desired_status = "verified" if assessment.status == "approved" and verified_incident else "suspected"
    if alert is None:
        alert = BreachAlert(
            alert_id=_new_id("BRA"), incident_id=assessment.incident_id, assessment_id=assessment.assessment_id,
            alert_type="customer_exposure", severity=severity, status=desired_status,
            title="Possible customer privacy exposure",
            summary="Masked evidence indicates possible customer information or credential exposure. Human review is required.",
            reason_codes=reason_codes, affected_subject_count=affected_count,
            credential_exposure_present=assessment.credential_exposure_present,
            public_exposure_present=assessment.public_exposure_present,
            external_access_confirmed=assessment.external_access_confirmed,
            requires_acknowledgement=True, deduplication_key=key,
            deduplication_signature=signature,
            deduplication_window_started_at=window_started_at,
            occurrence_count=1, duplicate_count=0,
            assessment_version=assessment.assessment_version,
            policy_version=assessment.taxonomy_version or "privacy-impact-default",
            last_observed_at=observed_at,
            acknowledgement_deadline=observed_at + timedelta(minutes=settings.alert_default_acknowledgement_minutes),
            containment_deadline=observed_at + timedelta(minutes=settings.alert_default_containment_minutes),
            escalation_deadline=observed_at + timedelta(minutes=settings.alert_default_acknowledgement_minutes * 2),
        )
        db.add(alert)
        db.flush()
        audit_service.log_action(db, action="breach_alert_created", actor_id=actor_id, target_type="breach_alert", target_id=alert.alert_id,
            details={"incident_id": assessment.incident_id, "assessment_id": assessment.assessment_id, "severity": severity,
                     "status": desired_status, "reason_codes": reason_codes, "affected_subject_count": affected_count})
    else:
        alert.occurrence_count = int(alert.occurrence_count or 1) + 1
        alert.duplicate_count = int(alert.duplicate_count or 0) + 1
        alert.last_observed_at = observed_at
        alert.assessment_id = assessment.assessment_id
        alert.assessment_version = assessment.assessment_version
        if alert.status not in _TERMINAL:
            alert.severity = severity
            alert.reason_codes = reason_codes
            alert.affected_subject_count = affected_count
            alert.credential_exposure_present = assessment.credential_exposure_present
            alert.public_exposure_present = assessment.public_exposure_present
            alert.external_access_confirmed = assessment.external_access_confirmed
            if alert.status in {"suspected", "verified"}:
                alert.status = desired_status
        audit_service.log_action(
            db, action="breach_alert_deduplicated", actor_id=actor_id,
            target_type="breach_alert", target_id=alert.alert_id,
            details={"incident_id": assessment.incident_id, "assessment_id": assessment.assessment_id,
                     "occurrence_count": alert.occurrence_count, "deduplication_window_started_at": window_started_at.isoformat()},
        )
    _recommend_containment(db, assessment, actor_id=actor_id)
    return alert


def list_alerts(db: Session, incident_id: str) -> list[BreachAlert]:
    return list(db.scalars(select(BreachAlert).where(BreachAlert.incident_id == incident_id).order_by(BreachAlert.triggered_at.desc())).all())


def _get(db: Session, alert_id: str, *, lock: bool = False) -> BreachAlert:
    stmt = select(BreachAlert).where(BreachAlert.alert_id == alert_id)
    if lock:
        stmt = stmt.with_for_update()
    alert = db.scalar(stmt)
    if alert is None:
        raise BreachAlertNotFoundError(f"Breach alert not found: {alert_id}")
    return alert


def acknowledge(db: Session, alert_id: str, *, actor_id: int) -> BreachAlert:
    alert = _get(db, alert_id, lock=True)
    if alert.status in _TERMINAL:
        raise BreachAlertStateError("A resolved alert cannot be acknowledged.")
    alert.status = "acknowledged"
    alert.acknowledged_by = actor_id
    alert.acknowledged_at = datetime.now(timezone.utc)
    audit_service.log_action(db, action="breach_alert_acknowledged", actor_id=actor_id, target_type="breach_alert", target_id=alert_id,
        details={"incident_id": alert.incident_id, "status": alert.status})
    db.commit(); db.refresh(alert)
    return alert


def resolve(db: Session, alert_id: str, *, actor_id: int, reason: str, false_positive: bool = False) -> BreachAlert:
    alert = _get(db, alert_id, lock=True)
    if alert.status in _TERMINAL:
        raise BreachAlertStateError("Alert is already in a terminal state.")
    safe_reason = audit_safety_service.mask_sensitive_text(reason.strip())
    alert.status = "false_positive" if false_positive else "resolved"
    alert.resolved_by = actor_id
    alert.resolved_at = datetime.now(timezone.utc)
    alert.resolution_reason = safe_reason
    audit_service.log_action(db, action="breach_alert_false_positive" if false_positive else "breach_alert_resolved", actor_id=actor_id,
        target_type="breach_alert", target_id=alert_id, details={"incident_id": alert.incident_id, "status": alert.status, "reason": safe_reason})
    db.commit(); db.refresh(alert)
    return alert


