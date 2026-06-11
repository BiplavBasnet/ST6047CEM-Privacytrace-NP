from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.enums import Severity
from app.models.sensitive_data_classification import SensitiveDataClassification
from app.schemas.contextual_detection_schema import ContextualDetectionResult
from app.services import (
    contextual_detection_service,
    sensitive_data_classification_service,
    taxonomy_registry_service,
)


def classify_fields(
    fields: dict[str, Any] | None,
    *,
    source_context: dict[str, str] | None = None,
    allow_fingerprint: bool = True,
) -> list[ContextualDetectionResult]:
    settings = get_settings()
    if not settings.nepal_financial_taxonomy_enabled or not fields:
        return []
    return contextual_detection_service.classify_structured_fields(
        fields,
        source_context=source_context,
        hmac_key=settings.detection_hmac_key if allow_fingerprint else "",
    )


def persist_results(
    db: Session,
    results: list[ContextualDetectionResult],
    *,
    incident_id: str | None = None,
    detection_id: str | None = None,
    privacy_alert_id: str | None = None,
    evidence_id: str | None = None,
    normalized_event_id: str | None = None,
    actor_id: int | None = None,
) -> list[SensitiveDataClassification]:
    return [
        sensitive_data_classification_service.persist_result(
            db,
            result,
            incident_id=incident_id,
            detection_id=detection_id,
            privacy_alert_id=privacy_alert_id,
            evidence_id=evidence_id,
            normalized_event_id=normalized_event_id,
            actor_id=actor_id,
            commit=False,
        )
        for result in results
    ]


def classify_and_persist(
    db: Session,
    fields: dict[str, Any] | None,
    *,
    source_context: dict[str, str] | None = None,
    allow_fingerprint: bool = True,
    incident_id: str | None = None,
    detection_id: str | None = None,
    privacy_alert_id: str | None = None,
    evidence_id: str | None = None,
    normalized_event_id: str | None = None,
    actor_id: int | None = None,
) -> list[SensitiveDataClassification]:
    results = classify_fields(
        fields,
        source_context=source_context,
        allow_fingerprint=allow_fingerprint,
    )
    return persist_results(
        db,
        results,
        incident_id=incident_id,
        detection_id=detection_id,
        privacy_alert_id=privacy_alert_id,
        evidence_id=evidence_id,
        normalized_event_id=normalized_event_id,
        actor_id=actor_id,
    )


def attach_alert_classifications(
    db: Session,
    privacy_alert_id: str,
    *,
    incident_id: str | None = None,
    evidence_id: str | None = None,
    normalized_event_id: str | None = None,
) -> list[SensitiveDataClassification]:
    rows = list(
        db.scalars(
            select(SensitiveDataClassification).where(
                SensitiveDataClassification.privacy_alert_id == privacy_alert_id
            )
        ).all()
    )
    for row in rows:
        if incident_id:
            row.incident_id = incident_id
        if evidence_id:
            row.evidence_id = evidence_id
        if normalized_event_id:
            row.normalized_event_id = normalized_event_id
    return rows


def severity_for_results(results: list[ContextualDetectionResult]) -> Severity:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    registry = taxonomy_registry_service.load_taxonomy()
    levels = [
        str(registry.category(result.taxonomy_code).get("default_severity") or "medium")
        for result in results
    ]
    level = max(levels, key=lambda item: order.get(item, 1), default="medium")
    return Severity(level)


def refresh_exposure_profiles(
    db: Session,
    incident_id: str | None,
    *,
    actor_id: int | None,
) -> None:
    settings = get_settings()
    if not incident_id or not settings.combined_exposure_rules_enabled:
        return
    from app.services import exposure_profile_service

    exposure_profile_service.recalculate_profiles(
        db,
        incident_id,
        actor_id=actor_id,
        commit=False,
    )
