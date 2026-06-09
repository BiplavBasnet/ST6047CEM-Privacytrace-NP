from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from statistics import median
from typing import Any
import re

import yaml

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings, resolve_rules_dir
from app.models.breach_alert import BreachAlert, BreachAlertEvidenceLink
from app.models.containment_action import ContainmentAction
from app.models.customer_notification import NotificationOutbox
from app.models.evidence_file import EvidenceFile
from app.schemas.alert_operations_schema import AlertMetricsRead, OperationalAlertRead, OverdueAlertRead
from app.services import audit_safety_service, audit_service


class AlertOperationError(ValueError):
    pass


class AlertNotFoundError(AlertOperationError):
    pass


TERMINAL_STATUSES = {"resolved", "false_positive", "cancelled"}
ACTIVE_STATUSES = {"suspected", "verified", "acknowledged", "contained"}
ESCALATION_ORDER = {
    "none": 0,
    "team_lead": 1,
    "incident_manager": 2,
    "security_lead": 3,
    "executive_review": 4,
    "regulatory_review_recommended": 5,
}


@lru_cache(maxsize=4)
def _load_policy(path_text: str) -> dict[str, Any]:
    try:
        payload = yaml.safe_load(Path(path_text).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AlertOperationError("Breach-alert operations policy is unavailable.") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("levels"), list):
        raise AlertOperationError("Breach-alert operations policy is invalid.")
    levels = [str(level) for level in payload["levels"]]
    if levels != list(ESCALATION_ORDER):
        raise AlertOperationError("Breach-alert escalation levels are invalid or out of order.")
    return payload


def load_alert_operations_policy(path: str | Path | None = None) -> dict[str, Any]:
    resolved = Path(path) if path else resolve_rules_dir() / "breach_alert_operations_rules.yaml"
    return _load_policy(str(resolved.resolve()))


def _now(value: datetime | None = None) -> datetime:
    return value or datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def _safe_reason(reason: str) -> str:
    safe = audit_safety_service.prepare_review_comment(reason)
    if not safe:
        raise AlertOperationError("A reason is required.")
    return safe


def _safe_label(value: str | None, *, field: str, maximum: int = 128) -> str | None:
    label = (value or "").strip()
    if not label:
        return None
    if len(label) > maximum or not re.fullmatch(r"[A-Za-z0-9 _./:@-]+", label):
        raise AlertOperationError(f"{field} contains unsupported characters.")
    return label


def is_suppressed(alert: BreachAlert, *, now: datetime | None = None) -> bool:
    if alert.suppression_started_at is None:
        return False
    expires = _aware(alert.suppression_expires_at)
    return expires is None or expires > _now(now)


def overdue_reasons(alert: BreachAlert, *, now: datetime | None = None) -> list[str]:
    current = _now(now)
    if alert.status in TERMINAL_STATUSES or is_suppressed(alert, now=current):
        return []
    reasons: list[str] = []
    acknowledgement_deadline = _aware(alert.acknowledgement_deadline)
    containment_deadline = _aware(alert.containment_deadline)
    escalation_deadline = _aware(alert.escalation_deadline)
    if acknowledgement_deadline and alert.acknowledged_at is None and acknowledgement_deadline < current:
        reasons.append("acknowledgement_deadline_exceeded")
    if containment_deadline and alert.status != "contained" and containment_deadline < current:
        reasons.append("containment_deadline_exceeded")
    if escalation_deadline and escalation_deadline < current:
        reasons.append("escalation_deadline_exceeded")
    return reasons


def recommended_escalation_level(
    alert: BreachAlert,
    reasons: list[str],
    *,
    failed_containment: bool = False,
    failed_notification_delivery: bool = False,
    integrity_failure: bool = False,
) -> str:
    severity = str(alert.severity).lower()
    selected = "none"
    context_flags = {
        "failed_containment": failed_containment,
        "failed_notification_delivery": failed_notification_delivery,
        "integrity_failure": integrity_failure,
    }
    for rule in load_alert_operations_policy().get("rules", []):
        severities = {str(item) for item in rule.get("severity_any") or []}
        if severities and severity not in severities:
            continue
        if rule.get("credential_exposure") and not alert.credential_exposure_present:
            continue
        if rule.get("unacknowledged_past_deadline") and "acknowledgement_deadline_exceeded" not in reasons:
            continue
        if rule.get("minimum_affected_subjects") and int(alert.affected_subject_count or 0) < int(rule["minimum_affected_subjects"]):
            continue
        if rule.get("confirmed_external_access") and not alert.external_access_confirmed:
            continue
        # A rule that requires one of these context flags only matches when
        # that condition is actually true; rules that don't reference the
        # flag at all are unaffected (previously such rules could never match
        # because the flag's mere presence in the policy caused a skip).
        if any(rule.get(flag) and not is_true for flag, is_true in context_flags.items()):
            continue
        level = str(rule.get("level") or "none")
        if ESCALATION_ORDER.get(level, -1) > ESCALATION_ORDER[selected]:
            selected = level
    return selected


def _elapsed_seconds(start: datetime | None, end: datetime | None) -> float | None:
    start_aware, end_aware = _aware(start), _aware(end)
    if not start_aware or not end_aware or end_aware < start_aware:
        return None
    return (end_aware - start_aware).total_seconds()


def calculate_metrics(
    alerts: list[BreachAlert],
    *,
    containment_actions: list[ContainmentAction] | None = None,
    notification_outbox: list[NotificationOutbox] | None = None,
    now: datetime | None = None,
) -> AlertMetricsRead:
    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}
    acknowledgement_times: list[float] = []
    containment_times: list[float] = []
    actions_by_incident: dict[str, list[ContainmentAction]] = {}
    for action in containment_actions or []:
        actions_by_incident.setdefault(action.incident_id, []).append(action)
    contained_by_incident: dict[str, datetime] = {}
    for incident_id, actions in actions_by_incident.items():
        if actions and all(action.status == "executed" and action.executed_at for action in actions):
            contained_by_incident[incident_id] = max(
                (action.executed_at for action in actions if action.executed_at is not None),
            )
    for alert in alerts:
        severity, status = str(alert.severity).lower(), str(alert.status).lower()
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1
        acknowledgement = _elapsed_seconds(alert.triggered_at, alert.acknowledged_at)
        containment = _elapsed_seconds(
            alert.triggered_at,
            alert.contained_at or contained_by_incident.get(alert.incident_id),
        )
        if acknowledgement is not None:
            acknowledgement_times.append(acknowledgement)
        if containment is not None:
            containment_times.append(containment)
    return AlertMetricsRead(
        total_alerts=len(alerts),
        active_alerts=sum(1 for alert in alerts if alert.status in ACTIVE_STATUSES),
        unresolved_alert_count=sum(1 for alert in alerts if alert.status not in TERMINAL_STATUSES),
        alerts_by_severity=by_severity,
        alerts_by_status=by_status,
        duplicate_alerts_prevented=sum(max(0, int(alert.duplicate_count or 0)) for alert in alerts),
        suppressed_alerts=sum(1 for alert in alerts if is_suppressed(alert, now=now)),
        false_positive_alerts=sum(1 for alert in alerts if alert.status == "false_positive"),
        acknowledged_alerts=sum(1 for alert in alerts if alert.acknowledged_at is not None),
        unacknowledged_past_deadline=sum(
            1 for alert in alerts if "acknowledgement_deadline_exceeded" in overdue_reasons(alert, now=now)
        ),
        acknowledged_sample_size=len(acknowledgement_times),
        contained_sample_size=len(containment_times),
        median_acknowledgement_seconds=median(acknowledgement_times) if acknowledgement_times else None,
        median_containment_seconds=median(containment_times) if containment_times else None,
        escalated_alerts=sum(1 for alert in alerts if alert.escalation_level != "none"),
        reopened_alerts=sum(int(alert.reopened_count or 0) for alert in alerts),
        failed_containment_actions=sum(
            1 for action in containment_actions or [] if action.status in {"failed", "manual_action_required"}
        ),
        notification_delivery_failures=sum(
            1 for item in notification_outbox or [] if item.status == "failed"
        ),
        generated_at=_now(now),
    )


def _get_alert(db: Session, alert_id: str, *, lock: bool = False) -> BreachAlert:
    stmt = select(BreachAlert).where(BreachAlert.alert_id == alert_id)
    if lock:
        stmt = stmt.with_for_update()
    alert = db.scalar(stmt)
    if alert is None:
        raise AlertNotFoundError("Breach alert was not found.")
    return alert


def _read(alert: BreachAlert, evidence_ids: list[str] | None = None, *, now: datetime | None = None) -> OperationalAlertRead:
    payload = {column.name: getattr(alert, column.name) for column in BreachAlert.__table__.columns}
    payload["evidence_ids"] = evidence_ids or []
    payload["overdue"] = bool(overdue_reasons(alert, now=now))
    return OperationalAlertRead.model_validate(payload)


def list_alerts(
    db: Session,
    *,
    status: str | None = None,
    severity: str | None = None,
    assigned_user_id: int | None = None,
    include_suppressed: bool = False,
    limit: int = 200,
) -> list[OperationalAlertRead]:
    requested_limit = min(max(limit, 1), 500)
    stmt = select(BreachAlert).order_by(BreachAlert.triggered_at.desc()).limit(500)
    if status:
        stmt = stmt.where(BreachAlert.status == status)
    if severity:
        stmt = stmt.where(BreachAlert.severity == severity)
    if assigned_user_id:
        stmt = stmt.where(BreachAlert.assigned_user_id == assigned_user_id)
    alerts = list(db.scalars(stmt).all())
    links = list(
        db.scalars(
            select(BreachAlertEvidenceLink).where(
                BreachAlertEvidenceLink.alert_id.in_([item.alert_id for item in alerts] or [""])
            )
        ).all()
    )
    by_alert: dict[str, list[str]] = {}
    for link in links:
        by_alert.setdefault(link.alert_id, []).append(link.evidence_id)
    return [
        _read(alert, sorted(by_alert.get(alert.alert_id, [])))
        for alert in alerts
        if include_suppressed or not is_suppressed(alert)
    ][:requested_limit]


def get_alert_read(db: Session, alert_id: str) -> OperationalAlertRead:
    alert = _get_alert(db, alert_id)
    evidence_ids = list(db.scalars(select(BreachAlertEvidenceLink.evidence_id).where(BreachAlertEvidenceLink.alert_id == alert_id)).all())
    return _read(alert, sorted(evidence_ids))


def assign_alert(
    db: Session,
    alert_id: str,
    *,
    actor_id: int,
    assigned_user_id: int | None,
    assigned_team: str | None,
    reason: str,
    acknowledgement_deadline: datetime | None = None,
    containment_deadline: datetime | None = None,
    escalation_deadline: datetime | None = None,
) -> BreachAlert:
    alert = _get_alert(db, alert_id, lock=True)
    if alert.status in TERMINAL_STATUSES:
        raise AlertOperationError("A terminal alert cannot be assigned.")
    current = _now()
    for value in (acknowledgement_deadline, containment_deadline, escalation_deadline):
        aware_value = _aware(value) if value is not None else None
        if aware_value is not None and aware_value <= current:
            raise AlertOperationError("Operational deadlines must be in the future.")
    alert.assigned_user_id = assigned_user_id
    alert.assigned_team = _safe_label(assigned_team, field="Assigned team")
    alert.assigned_at = current
    if acknowledgement_deadline is not None:
        alert.acknowledgement_deadline = acknowledgement_deadline
    if containment_deadline is not None:
        alert.containment_deadline = containment_deadline
    if escalation_deadline is not None:
        alert.escalation_deadline = escalation_deadline
    audit_service.log_action(
        db,
        action="breach_alert_assigned",
        actor_id=actor_id,
        target_type="breach_alert",
        target_id=alert_id,
        details={"incident_id": alert.incident_id, "assigned_user_id": assigned_user_id, "assigned_team": alert.assigned_team, "reason": _safe_reason(reason)},
    )
    db.commit()
    db.refresh(alert)
    return alert


def suppress_alert(
    db: Session,
    alert_id: str,
    *,
    actor_id: int,
    reason: str,
    expires_at: datetime | None,
    policy_code: str | None = None,
    privileged_override: bool = False,
) -> BreachAlert:
    alert = _get_alert(db, alert_id, lock=True)
    if alert.status in TERMINAL_STATUSES:
        raise AlertOperationError("A terminal alert cannot be suppressed.")
    current = _now()
    expiry = _aware(expires_at)
    suppression_policy = load_alert_operations_policy().get("suppression", {})
    maximum_manual_days = int(suppression_policy.get("maximum_manual_days", 30))
    if expiry and expiry <= current:
        raise AlertOperationError("Suppression expiry must be in the future.")
    if expiry and expiry > current + timedelta(days=maximum_manual_days) and not privileged_override:
        raise AlertOperationError(f"Manual suppression cannot exceed {maximum_manual_days} days without privileged override.")
    if suppression_policy.get("critical_credential_requires_expiry", True) and alert.severity == "critical" and alert.credential_exposure_present and expiry is None:
        raise AlertOperationError("Critical credential alerts require a suppression expiry.")
    if suppression_policy.get("permanent_critical_override_required", True) and alert.severity == "critical" and expiry is None and not privileged_override:
        raise AlertOperationError("Permanent critical-alert suppression requires privileged override.")
    policy_code = _safe_label(policy_code, field="Policy code")
    allowed_codes = {str(item) for item in suppression_policy.get("allowed_policy_codes") or []}
    if policy_code and policy_code not in allowed_codes:
        raise AlertOperationError("Suppression policy code is not configured.")
    alert.suppression_type = "policy" if policy_code else "manual"
    alert.suppression_reason = _safe_reason(reason)
    alert.suppression_started_at = current
    alert.suppression_expires_at = expiry
    alert.suppressed_by = actor_id
    audit_service.log_action(
        db,
        action="breach_alert_suppressed",
        actor_id=actor_id,
        target_type="breach_alert",
        target_id=alert_id,
        details={"incident_id": alert.incident_id, "suppression_type": alert.suppression_type, "policy_code": policy_code, "expires_at": expiry, "reason": alert.suppression_reason},
    )
    db.commit()
    db.refresh(alert)
    return alert


def unsuppress_alert(db: Session, alert_id: str, *, actor_id: int, reason: str) -> BreachAlert:
    alert = _get_alert(db, alert_id, lock=True)
    if alert.suppression_started_at is None:
        raise AlertOperationError("The alert is not suppressed.")
    safe_reason = _safe_reason(reason)
    alert.suppression_type = None
    alert.suppression_reason = None
    alert.suppression_started_at = None
    alert.suppression_expires_at = None
    alert.suppressed_by = None
    audit_service.log_action(db, action="breach_alert_unsuppressed", actor_id=actor_id, target_type="breach_alert", target_id=alert_id, details={"incident_id": alert.incident_id, "reason": safe_reason})
    db.commit()
    db.refresh(alert)
    return alert


def escalate_alert(db: Session, alert_id: str, *, actor_id: int, level: str, reason: str) -> BreachAlert:
    if not get_settings().alert_escalation_enabled:
        raise AlertOperationError("Alert escalation is disabled by policy.")
    alert = _get_alert(db, alert_id, lock=True)
    if alert.status in TERMINAL_STATUSES:
        raise AlertOperationError("A terminal alert cannot be escalated.")
    levels = [str(item) for item in load_alert_operations_policy()["levels"]]
    order = {item: index for index, item in enumerate(levels)}
    if level not in order or order[level] <= order.get(alert.escalation_level, 0):
        raise AlertOperationError("Escalation must move to a higher supported level.")
    alert.escalation_level = level
    alert.escalation_reason = _safe_reason(reason)
    alert.escalated_at = _now()
    alert.escalated_by = actor_id
    audit_service.log_action(db, action="breach_alert_escalated", actor_id=actor_id, target_type="breach_alert", target_id=alert_id, details={"incident_id": alert.incident_id, "escalation_level": level, "reason": alert.escalation_reason})
    db.commit()
    db.refresh(alert)
    return alert


def reopen_alert(db: Session, alert_id: str, *, actor_id: int, reason: str) -> BreachAlert:
    alert = _get_alert(db, alert_id, lock=True)
    if alert.status not in TERMINAL_STATUSES:
        raise AlertOperationError("Only a terminal alert can be reopened.")
    current = _now()
    defaults = load_alert_operations_policy().get("defaults", {})
    alert.status = "suspected"
    alert.resolved_at = None
    alert.resolved_by = None
    alert.resolution_reason = None
    alert.contained_at = None
    alert.acknowledged_at = None
    alert.acknowledged_by = None
    alert.suppression_type = None
    alert.suppression_reason = None
    alert.suppression_started_at = None
    alert.suppression_expires_at = None
    alert.suppressed_by = None
    alert.escalation_level = "none"
    alert.escalation_reason = None
    alert.escalated_at = None
    alert.escalated_by = None
    alert.acknowledgement_deadline = current + timedelta(minutes=int(defaults.get("acknowledgement_minutes", 30)))
    alert.containment_deadline = current + timedelta(minutes=int(defaults.get("containment_minutes", 120)))
    alert.escalation_deadline = current + timedelta(minutes=int(defaults.get("escalation_minutes", 60)))
    alert.reopened_count = int(alert.reopened_count or 0) + 1
    alert.reopened_at = current
    alert.reopened_by = actor_id
    alert.reopen_reason = _safe_reason(reason)
    audit_service.log_action(db, action="breach_alert_reopened", actor_id=actor_id, target_type="breach_alert", target_id=alert_id, details={"incident_id": alert.incident_id, "reopened_count": alert.reopened_count, "reason": alert.reopen_reason})
    db.commit()
    db.refresh(alert)
    return alert


def link_evidence(db: Session, alert_id: str, evidence_id: str, *, actor_id: int) -> BreachAlertEvidenceLink:
    alert = _get_alert(db, alert_id, lock=True)
    if db.scalar(select(EvidenceFile.id).where(EvidenceFile.evidence_id == evidence_id)) is None:
        raise AlertOperationError("Evidence was not found.")
    existing = db.scalar(select(BreachAlertEvidenceLink).where(BreachAlertEvidenceLink.alert_id == alert_id, BreachAlertEvidenceLink.evidence_id == evidence_id))
    if existing:
        return existing
    link = BreachAlertEvidenceLink(alert_id=alert_id, evidence_id=evidence_id)
    db.add(link)
    audit_service.log_action(db, action="breach_alert_evidence_linked", actor_id=actor_id, target_type="breach_alert", target_id=alert_id, details={"incident_id": alert.incident_id, "evidence_id": evidence_id})
    db.commit()
    db.refresh(link)
    return link


def _escalation_context_by_incident(
    db: Session, incident_ids: set[str]
) -> tuple[set[str], set[str], set[str]]:
    """Look up real failed-containment/notification/integrity signals per incident."""
    if not incident_ids:
        return set(), set(), set()

    from app.models.customer_notification import CustomerNotificationDecision
    from app.models.integrity_ledger import IntegrityVerificationRun

    failed_containment_incidents = set(
        db.scalars(
            select(ContainmentAction.incident_id)
            .where(
                ContainmentAction.incident_id.in_(incident_ids),
                ContainmentAction.status.in_(["failed", "manual_action_required"]),
            )
            .distinct()
        ).all()
    )
    failed_notification_incidents = set(
        db.scalars(
            select(CustomerNotificationDecision.incident_id)
            .join(
                NotificationOutbox,
                NotificationOutbox.notification_id == CustomerNotificationDecision.notification_id,
            )
            .where(
                CustomerNotificationDecision.incident_id.in_(incident_ids),
                NotificationOutbox.status == "failed",
            )
            .distinct()
        ).all()
    )
    integrity_failure_incidents = set(
        db.scalars(
            select(IntegrityVerificationRun.scope_id)
            .where(
                IntegrityVerificationRun.scope_type == "incident",
                IntegrityVerificationRun.scope_id.in_(incident_ids),
                IntegrityVerificationRun.chain_valid.is_(False),
            )
            .distinct()
        ).all()
    )
    return failed_containment_incidents, failed_notification_incidents, integrity_failure_incidents


def overdue_alerts(db: Session, *, now: datetime | None = None) -> list[OverdueAlertRead]:
    alerts = list(db.scalars(select(BreachAlert).order_by(BreachAlert.triggered_at.desc())).all())
    incident_ids = {alert.incident_id for alert in alerts}
    failed_containment_incidents, failed_notification_incidents, integrity_failure_incidents = (
        _escalation_context_by_incident(db, incident_ids)
    )
    output: list[OverdueAlertRead] = []
    for alert in alerts:
        reasons = overdue_reasons(alert, now=now)
        if reasons:
            output.append(
                OverdueAlertRead(
                    alert=_read(alert, now=now),
                    overdue_reasons=reasons,
                    recommended_escalation_level=recommended_escalation_level(
                        alert,
                        reasons,
                        failed_containment=alert.incident_id in failed_containment_incidents,
                        failed_notification_delivery=alert.incident_id in failed_notification_incidents,
                        integrity_failure=alert.incident_id in integrity_failure_incidents,
                    ),
                )
            )
    return output


def metrics(db: Session, *, now: datetime | None = None) -> AlertMetricsRead:
    alerts = list(db.scalars(select(BreachAlert)).all())
    actions = list(db.scalars(select(ContainmentAction)).all())
    outbox = list(db.scalars(select(NotificationOutbox)).all())
    return calculate_metrics(alerts, containment_actions=actions, notification_outbox=outbox, now=now)


