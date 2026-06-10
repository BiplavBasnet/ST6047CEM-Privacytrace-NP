from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.breach_alert import BreachAlert
from app.models.breach_decision import BreachDecisionRecord
from app.models.containment_action import ContainmentAction
from app.models.customer_notification import CustomerNotificationDecision
from app.models.detection import Detection
from app.models.evidence_file import EvidenceFile
from app.models.fix_verification import FixVerification
from app.models.incident import Incident
from app.models.integrity_ledger import IntegrityLedgerRecord
from app.models.normalized_event import NormalizedEvent
from app.models.preventive_control import PreventiveControl
from app.models.privacy_alert import PrivacyAlert
from app.models.privacy_impact import PrivacyImpactAssessment
from app.models.remediation_action import RemediationAction
from app.models.review_decision import ReviewDecision
from app.schemas.incident_timeline_schema import IncidentTimelineEventRead, IncidentTimelineResponse
from app.services import taxonomy_registry_service


class IncidentTimelineError(ValueError):
    pass


def _utc(value: datetime | None) -> datetime:
    value = value or datetime.now(timezone.utc)
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _value(value: object | None) -> str | None:
    if value is None:
        return None
    return str(getattr(value, "value", value))


def _safe_category_code(value: str | None) -> str:
    code = (value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", code):
        return "unclassified_sensitive_data"
    try:
        if taxonomy_registry_service.load_taxonomy().category(code).get("internal_only"):
            return "restricted_compliance_information"
    except KeyError:
        if "restricted" in code.casefold() or "aml" in code.casefold():
            return "restricted_internal_exposure"
    return code


def timeline_event(
    *,
    event_id: str,
    incident_id: str,
    event_type: str,
    stage: str,
    event_timestamp: datetime | None,
    recorded_timestamp: datetime | None,
    source_type: str,
    source_id: str,
    summary: str,
    actor_type: str = "system",
    actor_id: str | int | None = None,
    evidence_ids: list[str] | None = None,
    status_before: str | None = None,
    status_after: str | None = None,
    reason: str | None = None,
    metadata: dict | None = None,
    integrity_record: IntegrityLedgerRecord | None = None,
) -> IncidentTimelineEventRead:
    event_time, recorded_time = _utc(event_timestamp), _utc(recorded_timestamp or event_timestamp)
    if event_timestamp is None:
        time_status = "unknown_original_time"
    elif recorded_time > event_time and (recorded_time - event_time).total_seconds() > 300:
        time_status = "delayed_ingestion"
    else:
        time_status = "observed"
    return IncidentTimelineEventRead(
        id=event_id,
        incident_id=incident_id,
        event_type=event_type,
        lifecycle_stage=stage,
        event_timestamp=event_time,
        recorded_timestamp=recorded_time,
        time_status=time_status,
        actor_type=actor_type,
        actor_id=str(actor_id) if actor_id is not None else None,
        source_type=source_type,
        source_id=source_id,
        evidence_ids=sorted(set(evidence_ids or [])),
        status_before=status_before,
        status_after=status_after,
        reason=reason,
        summary=summary,
        metadata=metadata or {},
        integrity_record_id=integrity_record.integrity_record_id if integrity_record else None,
        integrity_status=integrity_record.verification_status if integrity_record else "not_yet_verified",
    )


def sort_events(events: Iterable[IncidentTimelineEventRead]) -> list[IncidentTimelineEventRead]:
    return sorted(events, key=lambda item: (item.event_timestamp, item.recorded_timestamp, item.id))


def _integrity_map(db: Session, incident_id: str) -> dict[tuple[str, str], IntegrityLedgerRecord]:
    rows = list(db.scalars(select(IntegrityLedgerRecord).where(IntegrityLedgerRecord.scope_type == "incident", IntegrityLedgerRecord.scope_id == incident_id)).all())
    return {(row.record_type, row.record_id): row for row in rows}


def build_timeline(
    db: Session,
    incident_id: str,
    *,
    event_type: str | None = None,
    lifecycle_stage: str | None = None,
    limit: int = 500,
) -> IncidentTimelineResponse:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise IncidentTimelineError("Incident was not found.")
    integrity = _integrity_map(db, incident_id)
    events: list[IncidentTimelineEventRead] = [timeline_event(
        event_id=f"incident:{incident_id}:created",
        incident_id=incident_id,
        event_type="incident_created",
        stage="overview",
        event_timestamp=incident.created_at,
        recorded_timestamp=incident.created_at,
        source_type="incident",
        source_id=incident_id,
        summary="Incident record created.",
        status_after=_value(incident.status),
        integrity_record=integrity.get(("incident", incident_id)),
    )]

    for item in db.scalars(select(EvidenceFile).where(EvidenceFile.linked_incident_id == incident_id)).all():
        events.append(timeline_event(event_id=f"evidence:{item.evidence_id}", incident_id=incident_id, event_type="evidence_imported", stage="root_cause_traceability", event_timestamp=item.upload_timestamp, recorded_timestamp=item.upload_timestamp, source_type="evidence", source_id=item.evidence_id, summary="Supporting evidence imported.", actor_type="user" if item.uploaded_by else "system", actor_id=item.uploaded_by, evidence_ids=[item.evidence_id], status_after=_value(item.parsing_status), metadata={"evidence_type": _value(item.evidence_type)}, integrity_record=integrity.get(("evidence", item.evidence_id))))
    for item in db.scalars(select(NormalizedEvent).where(NormalizedEvent.linked_incident_id == incident_id)).all():
        events.append(timeline_event(event_id=f"event:{item.event_id}", incident_id=incident_id, event_type="source_event_observed", stage="root_cause_traceability", event_timestamp=item.timestamp, recorded_timestamp=incident.created_at, source_type="normalized_event", source_id=item.event_id, summary="A source event was correlated with the incident.", evidence_ids=[item.evidence_id], metadata={"source_type": item.source_type, "event_type": item.event_type}, integrity_record=integrity.get(("normalized_event", item.event_id))))
    for item in db.scalars(select(Detection).where(Detection.incident_id == incident_id)).all():
        events.append(timeline_event(event_id=f"detection:{item.detection_id}", incident_id=incident_id, event_type="sensitive_data_detected", stage="overview", event_timestamp=item.created_at, recorded_timestamp=item.created_at, source_type="detection", source_id=item.detection_id, summary="A masked sensitive-data category was detected.", evidence_ids=[item.evidence_id] if item.evidence_id else [], metadata={"sensitive_type": _safe_category_code(item.sensitive_type), "severity": _value(item.severity)}, integrity_record=integrity.get(("detection", item.detection_id))))
    for item in db.scalars(select(PrivacyAlert).where(PrivacyAlert.linked_incident_id == incident_id)).all():
        events.append(timeline_event(event_id=f"privacy-alert:{item.alert_id}", incident_id=incident_id, event_type="privacy_alert_created", stage="overview", event_timestamp=item.alert_time, recorded_timestamp=item.received_at, source_type="privacy_alert", source_id=item.alert_id, summary="An internal privacy alert was created.", evidence_ids=[item.evidence_id] if item.evidence_id else [], status_after=item.status, metadata={"severity": _value(item.severity)}, integrity_record=integrity.get(("privacy_alert", item.alert_id))))
    for item in db.scalars(select(BreachAlert).where(BreachAlert.incident_id == incident_id)).all():
        events.append(timeline_event(event_id=f"breach-alert:{item.alert_id}", incident_id=incident_id, event_type="breach_alert_created", stage="privacy_impact", event_timestamp=item.triggered_at, recorded_timestamp=item.triggered_at, source_type="breach_alert", source_id=item.alert_id, summary="An assessed exposure alert was created for internal review.", status_after=item.status, metadata={"severity": item.severity, "alert_type": _safe_category_code(item.alert_type)}, integrity_record=integrity.get(("breach_alert", item.alert_id))))
        if item.acknowledged_at:
            events.append(timeline_event(event_id=f"breach-alert:{item.alert_id}:ack", incident_id=incident_id, event_type="breach_alert_acknowledged", stage="privacy_impact", event_timestamp=item.acknowledged_at, recorded_timestamp=item.acknowledged_at, source_type="breach_alert", source_id=item.alert_id, summary="The exposure alert was acknowledged.", actor_type="user", actor_id=item.acknowledged_by, status_after="acknowledged"))
    for item in db.scalars(select(PrivacyImpactAssessment).where(PrivacyImpactAssessment.incident_id == incident_id)).all():
        events.append(timeline_event(event_id=f"assessment:{item.assessment_id}", incident_id=incident_id, event_type="privacy_impact_assessed", stage="privacy_impact", event_timestamp=item.created_at, recorded_timestamp=item.created_at, source_type="privacy_impact_assessment", source_id=item.assessment_id, summary="An explainable privacy-impact assessment was generated.", actor_type="user" if item.created_by else "system", actor_id=item.created_by, status_after=item.status, metadata={"assessment_version": item.assessment_version, "breach_severity_level": item.breach_severity_level, "privacy_harm_level": item.privacy_harm_level}, integrity_record=integrity.get(("privacy_impact_assessment", item.assessment_id))))
    for item in db.scalars(select(BreachDecisionRecord).where(BreachDecisionRecord.incident_id == incident_id)).all():
        events.append(timeline_event(event_id=f"decision:{item.decision_id}", incident_id=incident_id, event_type="breach_decision_recorded", stage="human_review", event_timestamp=item.created_at, recorded_timestamp=item.created_at, source_type="breach_decision", source_id=item.decision_id, summary="A versioned breach decision was recorded for human review.", actor_type="user" if item.created_by else "system", actor_id=item.created_by, evidence_ids=item.input_evidence_ids, status_after=item.status, metadata={"decision_version": item.decision_version, "breach_determination": item.breach_determination}, integrity_record=integrity.get(("breach_decision", item.decision_id))))
    for item in db.scalars(select(ReviewDecision).where(ReviewDecision.incident_id == incident_id)).all():
        events.append(timeline_event(event_id=f"review:{item.id}", incident_id=incident_id, event_type="human_review_submitted", stage="human_review", event_timestamp=item.timestamp, recorded_timestamp=item.timestamp, source_type="review_decision", source_id=str(item.id), summary="A human review decision was submitted.", actor_type="user", actor_id=item.reviewer_id, evidence_ids=item.evidence_relied_on, status_after=item.decision))
    for item in db.scalars(select(RemediationAction).where(RemediationAction.incident_id == incident_id)).all():
        events.append(timeline_event(event_id=f"remediation:{item.remediation_action_id}", incident_id=incident_id, event_type="remediation_action_created", stage="remediation", event_timestamp=item.created_at, recorded_timestamp=item.created_at, source_type="remediation_action", source_id=item.remediation_action_id, summary="A remediation action was recorded.", actor_type="user" if item.created_by else "system", actor_id=item.created_by, status_after=item.status, metadata={"action_type": item.action_type, "priority": item.priority}))
    for item in db.scalars(select(ContainmentAction).where(ContainmentAction.incident_id == incident_id)).all():
        events.append(timeline_event(event_id=f"containment:{item.containment_action_id}", incident_id=incident_id, event_type="containment_action_recorded", stage="remediation", event_timestamp=item.created_at, recorded_timestamp=item.created_at, source_type="containment_action", source_id=item.containment_action_id, summary="A credential-containment action was recorded.", status_after=item.status, metadata={"action_type": item.action_type, "requires_approval": item.requires_approval}, integrity_record=integrity.get(("containment_action", item.containment_action_id))))
    for item in db.scalars(select(PreventiveControl).where(PreventiveControl.incident_id == incident_id)).all():
        events.append(timeline_event(event_id=f"control:{item.control_id}", incident_id=incident_id, event_type="preventive_control_proposed", stage="remediation", event_timestamp=item.created_at, recorded_timestamp=item.created_at, source_type="preventive_control", source_id=item.control_id, summary="A preventive control was proposed for review.", actor_type="user" if item.created_by else "system", actor_id=item.created_by, status_after=item.status, metadata={"control_type": item.control_type, "source": item.source}, integrity_record=integrity.get(("preventive_control", item.control_id))))
    for item in db.scalars(select(FixVerification).where(FixVerification.incident_id == incident_id)).all():
        events.append(timeline_event(event_id=f"verification:{item.id}", incident_id=incident_id, event_type="fix_verification_completed", stage="fix_verification", event_timestamp=item.timestamp, recorded_timestamp=item.timestamp, source_type="fix_verification", source_id=str(item.id), summary="Fix verification completed with a reviewed status.", evidence_ids=list(item.evidence_used or []), status_after=_value(item.verification_status)))
    for item in db.scalars(select(CustomerNotificationDecision).where(CustomerNotificationDecision.incident_id == incident_id)).all():
        events.append(timeline_event(event_id=f"notification:{item.notification_id}", incident_id=incident_id, event_type="customer_notification_decision", stage="final_report", event_timestamp=item.created_at, recorded_timestamp=item.updated_at, source_type="customer_notification", source_id=item.notification_id, summary="A reviewed customer-notification decision was recorded.", actor_type="user" if item.created_by else "system", actor_id=item.created_by, status_after=item.status, metadata={"recommendation": item.recommendation}, integrity_record=integrity.get(("customer_notification", item.notification_id))))

    audit_rows = db.scalars(select(AuditLog).where(AuditLog.target_id == incident_id).order_by(AuditLog.timestamp)).all()
    for item in audit_rows:
        events.append(timeline_event(event_id=f"audit:{item.id}", incident_id=incident_id, event_type="audit_transition", stage="audit", event_timestamp=item.timestamp, recorded_timestamp=item.timestamp, source_type="audit_log", source_id=str(item.id), summary=f"Audited transition: {item.action}.", actor_type="user" if item.actor_id else "system", actor_id=item.actor_id, metadata={"action": item.action, "target_type": item.target_type}, integrity_record=integrity.get(("audit_log", str(item.id)))))

    events = sort_events(events)
    if event_type:
        events = [item for item in events if item.event_type == event_type]
    if lifecycle_stage:
        events = [item for item in events if item.lifecycle_stage == lifecycle_stage]
    total = len(events)
    events = events[-min(max(limit, 1), 1000):]
    limitations = ["Events created before integrity-ledger enablement remain labelled not yet verified."]
    return IncidentTimelineResponse(incident_id=incident_id, events=events, total=total, limitations=limitations)

