from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.affected_subject import AffectedSubjectReference
from app.models.incident import Incident
from app.services import audit_service, privacy_response_provider_service


class AffectedSubjectError(Exception):
    pass


def _subject_reference(lookup_token: str) -> str:
    key = get_settings().subject_reference_hmac_key
    if not key:
        raise AffectedSubjectError("Subject-reference key is not configured.")
    digest = hmac.new(key.encode("utf-8"), lookup_token.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"SUBJ-H1-{digest}"


def resolve_subject(db: Session, incident_id: str, *, lookup_token: str, affected_data_categories: list[str], occurrence_count: int,
                    credential_types: list[str], actor_id: int, subject_type: str = "unknown_subject_type",
                    adapter: privacy_response_provider_service.CustomerDirectoryAdapter | None = None) -> AffectedSubjectReference:
    if db.scalar(select(Incident.id).where(Incident.incident_id == incident_id)) is None:
        raise AffectedSubjectError(f"Incident not found: {incident_id}")
    reference = _subject_reference(lookup_token)
    adapter = adapter or privacy_response_provider_service.get_customer_directory_adapter()
    try:
        resolution = adapter.resolve_subject(lookup_token, reference)
    finally:
        lookup_token = ""
    item = db.scalar(select(AffectedSubjectReference).where(AffectedSubjectReference.incident_id == incident_id, AffectedSubjectReference.subject_reference == reference))
    if item is None:
        item = AffectedSubjectReference(
            subject_reference_id=f"ASR-{uuid.uuid4().hex[:12].upper()}", incident_id=incident_id,
            subject_reference=reference, reference_method="hmac_sha256_v1",
            subject_type=subject_type,
            resolution_status="resolved" if resolution.active else "inactive",
            affected_data_categories=sorted(set(affected_data_categories)), occurrence_count=occurrence_count,
            credential_types=sorted(set(credential_types)), notification_eligibility="eligible" if resolution.active else "not_eligible",
            resolved_at=datetime.now(timezone.utc),
        )
        db.add(item)
    else:
        item.affected_data_categories = sorted(set(item.affected_data_categories or []) | set(affected_data_categories))
        if subject_type != "unknown_subject_type":
            item.subject_type = subject_type
        item.credential_types = sorted(set(item.credential_types or []) | set(credential_types))
        item.occurrence_count += occurrence_count
        item.resolution_status = "resolved" if resolution.active else "inactive"
        item.notification_eligibility = "eligible" if resolution.active else "not_eligible"
        item.resolved_at = datetime.now(timezone.utc)
    db.flush()
    audit_service.log_action(db, action="affected_subject_resolved", actor_id=actor_id, target_type="affected_subject_reference", target_id=item.subject_reference_id,
        details={"incident_id": incident_id, "reference_method": item.reference_method, "resolution_status": item.resolution_status,
                 "subject_type": item.subject_type, "affected_data_categories": item.affected_data_categories, "credential_types": item.credential_types})
    from app.services import privacy_breach_alert_service, privacy_impact_service
    assessment = privacy_impact_service.get_latest_assessment(db, incident_id)
    if assessment:
        privacy_breach_alert_service.evaluate_assessment(db, assessment, actor_id=actor_id)
    db.commit(); db.refresh(item)
    return item


def list_subjects(db: Session, incident_id: str) -> list[AffectedSubjectReference]:
    return list(db.scalars(select(AffectedSubjectReference).where(AffectedSubjectReference.incident_id == incident_id).order_by(AffectedSubjectReference.created_at)).all())
