"""Audit trail for security-relevant actions (no raw sensitive values in details)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.services import audit_safety_service, field_encryption_service

# Actions recorded across the workflow (extend in later phases as needed).
ACTION_LOGIN_SUCCESS = "login_success"
ACTION_LOGIN_FAILED = "login_failed"
ACTION_LOGOUT = "logout"
ACTION_REGISTRATION_SUCCEEDED = "registration_succeeded"
ACTION_REGISTRATION_REJECTED = "registration_rejected"
ACTION_REGISTRATION_DISABLED = "registration_disabled"
ACTION_PERMISSION_DENIED = "permission_denied"
ACTION_EVIDENCE_UPLOADED = "evidence_uploaded"
ACTION_SAMPLE_EVIDENCE_LOADED = "sample_evidence_loaded"
ACTION_EVIDENCE_PARSED = "evidence_parsed"
ACTION_DETECTION_COMPLETED = "detection_completed"
ACTION_DETECTION_RUN = "detection_run"
ACTION_INCIDENT_ANALYSED = "incident_analysed"
ACTION_EXPLANATION_GENERATED = "explanation_generated"
ACTION_REVIEW_SUBMITTED = "review_submitted"
ACTION_REVIEW_DRAFT_SAVED = "review_draft_saved"
ACTION_REVIEW_DRAFT_DELETED = "review_draft_deleted"
ACTION_REMEDIATION_CREATED = "remediation_action_created"
ACTION_REMEDIATION_UPDATED = "remediation_action_updated"
ACTION_CICD_EVIDENCE_IMPORTED = "cicd_evidence_imported"
ACTION_CICD_EVIDENCE_LINKED = "cicd_evidence_linked"
ACTION_FIX_VERIFICATION_COMPLETED = "fix_verification_completed"
ACTION_FIX_VERIFICATION_RUN = "fix_verification_run"
ACTION_REPORT_EXPORTED = "report_exported"
ACTION_REPORT_GENERATED = "report_generated"
ACTION_METRICS_GENERATED = "metrics_generated"
ACTION_USER_CREATED = "user_created"
ACTION_USER_UPDATED = "user_updated"
ACTION_USER_DEACTIVATED = "user_deactivated"
ACTION_CRYPTO_ENCRYPT = "crypto_encrypt"
ACTION_CRYPTO_DECRYPT = "crypto_decrypt"
ACTION_SCANNER_BRIDGE_IMPORT = "scanner_bridge_import"
ACTION_SCANNER_BRIDGE_REJECTED = "scanner_bridge_rejected"
ACTION_SCANNER_BRIDGE_LINKED = "scanner_bridge_linked"
ACTION_SCANNER_BRIDGE_CORRELATED = "scanner_bridge_correlated"


def log_action(
    db: Session,
    *,
    action: str,
    actor_id: int | None = None,
    actor_email: str | None = None,
    actor_role: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict | None = None,
    organisation_id: int | None = None,
) -> AuditLog:
    enriched: dict = dict(details or {})
    if actor_email:
        enriched.setdefault("actor_email", actor_email)
    if actor_role:
        enriched.setdefault("actor_role", actor_role)
    if organisation_id is None and actor_id is not None:
        from app.models.enums import MembershipStatus
        from app.models.organisation import OrganisationMembership

        membership = db.scalar(
            select(OrganisationMembership).where(
                OrganisationMembership.user_id == actor_id,
                OrganisationMembership.status == MembershipStatus.ACTIVE,
            )
        )
        if membership is not None:
            organisation_id = membership.organisation_id
    safe_details = audit_safety_service.validate_and_sanitize_audit_details(enriched)
    record_id = target_id or str(actor_id or "system")
    entry = AuditLog(
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        organisation_id=organisation_id,
    )
    if field_encryption_service.encryption_enabled():
        payload = field_encryption_service.encrypt_json(
            value=safe_details,
            table="audit_logs",
            record_id=record_id,
            field="details",
            extra=action,
        )
        entry.details = None
        entry.details_encrypted = payload
        entry.details_crypto_metadata = {"kid": payload.get("kid")}
        entry.is_encrypted = True
    else:
        entry.details = safe_details
        entry.is_encrypted = False
    db.add(entry)
    db.flush()
    from app.config import get_settings
    if get_settings().integrity_ledger_enabled:
        from app.services import integrity_ledger_service
        integrity_ledger_service.append_record(
            db, record_type="audit_event", record_id=str(entry.id),
            canonical_content={"id": entry.id, "action": entry.action, "target_type": entry.target_type, "target_id": entry.target_id, "timestamp": entry.timestamp, "details": safe_details},
            scope_type="incident" if safe_details.get("incident_id") else "global", scope_id=safe_details.get("incident_id"),
        )
    return entry


def resolve_audit_details(log: AuditLog) -> dict:
    if log.is_encrypted and log.details_encrypted:
        decrypted = field_encryption_service.decrypt_json(log.details_encrypted)
        return audit_safety_service.validate_and_sanitize_audit_details(decrypted)
    return log.details or {}


def audit_log_to_safe_read(log: AuditLog) -> dict:
    """Build a response-safe view of an audit log row."""
    details = resolve_audit_details(log)
    return {
        "id": log.id,
        "actor_id": log.actor_id,
        "actor_email": details.get("actor_email"),
        "actor_role": details.get("actor_role"),
        "action": log.action,
        "target_type": log.target_type,
        "target_id": log.target_id,
        "timestamp": log.timestamp,
        "details": audit_safety_service.sanitize_audit_details_for_response(details),
        "is_encrypted": log.is_encrypted,
    }


def list_audit_logs(
    db: Session,
    *,
    incident_id: str | None = None,
    action: str | None = None,
    limit: int = 100,
    organisation_id: int | None = None,
) -> list[AuditLog]:
    stmt = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if organisation_id is not None:
        stmt = stmt.where(
            (AuditLog.organisation_id == organisation_id) | (AuditLog.organisation_id.is_(None))
        )
    rows = list(db.scalars(stmt).all())
    if not incident_id:
        return rows
    filtered: list[AuditLog] = []
    for row in rows:
        if row.target_id == incident_id:
            filtered.append(row)
            continue
        details = resolve_audit_details(row)
        if details.get("incident_id") == incident_id:
            filtered.append(row)
    return filtered
