from __future__ import annotations

import hashlib
import json
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.sensitive_data_classification import SensitiveDataClassification
from app.schemas.contextual_detection_schema import ContextualDetectionResult
from app.services import audit_service, restricted_data_policy_service


def _classification_key(*, incident_id: str | None, detection_id: str | None, evidence_id: str | None, result: ContextualDetectionResult) -> str:
    payload = {
        "incident_id": incident_id,
        "detection_id": detection_id,
        "evidence_id": evidence_id,
        "taxonomy_code": result.taxonomy_code,
        "taxonomy_version": result.taxonomy_version,
        "fingerprint": result.value_fingerprint,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def persist_result(
    db: Session,
    result: ContextualDetectionResult,
    *,
    incident_id: str | None = None,
    detection_id: str | None = None,
    privacy_alert_id: str | None = None,
    evidence_id: str | None = None,
    normalized_event_id: str | None = None,
    affected_subject_reference_id: str | None = None,
    actor_id: int | None = None,
    commit: bool = True,
) -> SensitiveDataClassification:
    key = _classification_key(incident_id=incident_id, detection_id=detection_id, evidence_id=evidence_id, result=result)
    existing = db.scalar(select(SensitiveDataClassification).where(SensitiveDataClassification.classification_key == key))
    if existing:
        return existing
    item = SensitiveDataClassification(
        classification_id=f"CLS-{uuid4().hex[:20].upper()}",
        classification_key=key,
        detection_id=detection_id,
        privacy_alert_id=privacy_alert_id,
        incident_id=incident_id,
        evidence_id=evidence_id,
        normalized_event_id=normalized_event_id,
        affected_subject_reference_id=affected_subject_reference_id,
        taxonomy_code=result.taxonomy_code,
        taxonomy_version=result.taxonomy_version,
        category_group=result.category_group,
        detection_method=result.detection_method,
        matched_alias=result.matched_alias,
        context_score=result.context_score,
        format_validation_status=result.format_validation_status,
        source_context_status=result.source_context_status,
        credential_status=result.credential_status,
        document_type=result.document_type,
        masked_value=result.masked_value,
        value_fingerprint=result.value_fingerprint,
        fingerprint_strategy=result.fingerprint_strategy,
        confidence_label=result.confidence_label,
        review_status=result.review_status,
        internal_only=result.internal_only,
        customer_notification_allowed=result.customer_notification_allowed,
        restricted_roles=result.restricted_roles,
        limitations=result.limitations,
    )
    db.add(item)
    audit_service.log_action(
        db,
        action="sensitive_data_classified",
        actor_id=actor_id,
        target_type="sensitive_data_classification",
        target_id=item.classification_id,
        details={
            "incident_id": incident_id,
            "detection_id": detection_id,
            "evidence_id": evidence_id,
            "taxonomy_code": "restricted_compliance_information" if result.internal_only else result.taxonomy_code,
            "taxonomy_version": result.taxonomy_version,
            "confidence_label": result.confidence_label,
            "internal_only": result.internal_only,
        },
    )
    if commit:
        db.commit()
        db.refresh(item)
    return item


def _safe_record(item: SensitiveDataClassification) -> dict:
    return {
        "classification_id": item.classification_id,
        "incident_id": item.incident_id,
        "detection_id": item.detection_id,
        "evidence_id": item.evidence_id,
        "taxonomy_code": item.taxonomy_code,
        "taxonomy_version": item.taxonomy_version,
        "category_group": item.category_group,
        "detection_method": item.detection_method,
        "context_score": item.context_score,
        "format_validation_status": item.format_validation_status,
        "source_context_status": item.source_context_status,
        "credential_status": item.credential_status,
        "document_type": item.document_type,
        "masked_value": item.masked_value,
        "confidence_label": item.confidence_label,
        "review_status": item.review_status,
        "internal_only": item.internal_only,
        "customer_notification_allowed": item.customer_notification_allowed,
        "limitations": item.limitations,
        "created_at": item.created_at,
    }


def list_classifications(
    db: Session,
    incident_id: str,
    *,
    authorised_restricted_access: bool = False,
) -> tuple[list[dict], bool]:
    rows = list(db.scalars(select(SensitiveDataClassification).where(SensitiveDataClassification.incident_id == incident_id).order_by(SensitiveDataClassification.created_at.desc())).all())
    records, restricted_present = restricted_data_policy_service.filter_records(
        [_safe_record(item) for item in rows],
        channel="restricted_api" if authorised_restricted_access else "ordinary_api",
        authorised_restricted_access=authorised_restricted_access,
    )
    return records, restricted_present
