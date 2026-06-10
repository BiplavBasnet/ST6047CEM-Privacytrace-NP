from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.models.integrity_ledger import (
    IntegrityLedgerHead,
    IntegrityLedgerRecord,
    IntegrityVerificationRun,
)

INTEGRITY_SCHEMA_VERSION = "1"
GENESIS_HASH = None


class IntegrityError(Exception):
    pass


class IntegrityNotFoundError(IntegrityError):
    pass


class IntegrityExportBlockedError(IntegrityError):
    pass


@dataclass(frozen=True)
class ChainVerificationSummary:
    records_checked: int
    chain_valid: bool
    content_mismatch_count: int
    missing_sequence_count: int
    invalid_link_count: int
    first_invalid_sequence: int | None


def _normalise(value: Any) -> Any:
    if isinstance(value, datetime):
        aware = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return aware.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(key): _normalise(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple)):
        return [_normalise(item) for item in value]
    if isinstance(value, set):
        return sorted((_normalise(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, float) and (value != value or value in {float("inf"), float("-inf")}):
        raise IntegrityError("Non-finite numbers cannot be integrity hashed.")
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(_normalise(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def sha256_text(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def calculate_record_hash(
    *, record_type: str, record_id: str, content_hash: str, sequence_number: int,
    previous_record_hash: str | None, created_at: datetime, schema_version: str,
) -> str:
    return sha256_text(canonical_json({
        "record_type": record_type,
        "record_id": record_id,
        "content_hash": content_hash,
        "sequence_number": sequence_number,
        "previous_record_hash": previous_record_hash,
        "created_at": created_at,
        "schema_version": schema_version,
    }))


def append_record(
    db: Session, *, record_type: str, record_id: str, canonical_content: dict,
    scope_type: str | None = None, scope_id: str | None = None,
    schema_version: str = INTEGRITY_SCHEMA_VERSION,
    integrity_record_id: str | None = None,
) -> IntegrityLedgerRecord:
    content_hash = sha256_text(canonical_json(canonical_content))
    head = _lock_ledger_head(db)
    existing = db.scalar(select(IntegrityLedgerRecord).where(
        IntegrityLedgerRecord.record_type == record_type,
        IntegrityLedgerRecord.record_id == record_id,
        IntegrityLedgerRecord.content_hash == content_hash,
    ))
    if existing is not None:
        return existing

    sequence = head.last_sequence_number + 1
    created_at = datetime.now(timezone.utc)
    record = IntegrityLedgerRecord(
        integrity_record_id=integrity_record_id or f"ILR-{uuid.uuid4().hex[:20].upper()}",
        sequence_number=sequence,
        record_type=record_type,
        record_id=record_id,
        scope_type=scope_type,
        scope_id=scope_id,
        content_hash=content_hash,
        previous_record_hash=head.last_record_hash,
        record_hash=calculate_record_hash(
            record_type=record_type, record_id=record_id, content_hash=content_hash,
            sequence_number=sequence, previous_record_hash=head.last_record_hash,
            created_at=created_at, schema_version=schema_version,
        ),
        integrity_schema_version=schema_version,
        created_at=created_at,
        verification_status="not_yet_verified",
    )
    db.add(record)
    db.flush()
    head.last_sequence_number = sequence
    head.last_record_hash = record.record_hash
    db.flush()
    return record


def _acquire_ledger_lock(db: Session) -> None:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext('privacytrace_integrity_ledger'))"))


def _lock_ledger_head(db: Session) -> IntegrityLedgerHead:
    _acquire_ledger_lock(db)
    head = db.scalar(
        select(IntegrityLedgerHead)
        .where(IntegrityLedgerHead.id == 1)
        .with_for_update()
    )
    if head is not None:
        return head
    record_count = int(db.scalar(select(func.count(IntegrityLedgerRecord.id))) or 0)
    if record_count:
        raise IntegrityError("Integrity ledger head is missing; append is blocked until privileged review.")
    head = IntegrityLedgerHead(id=1, last_sequence_number=0, last_record_hash=GENESIS_HASH)
    db.add(head)
    db.flush()
    return head


def verify_chain(
    records: Iterable[IntegrityLedgerRecord],
    content_resolver: Callable[[IntegrityLedgerRecord], dict | None] | None = None,
    *,
    expected_head: IntegrityLedgerHead | None = None,
    require_head: bool = False,
) -> ChainVerificationSummary:
    ordered = sorted(records, key=lambda item: item.sequence_number)
    expected_sequence = 1
    previous_hash: str | None = GENESIS_HASH
    content_mismatches = missing_sequences = invalid_links = 0
    first_invalid: int | None = None
    for record in ordered:
        if record.sequence_number != expected_sequence:
            gap = max(1, record.sequence_number - expected_sequence)
            missing_sequences += gap
            first_invalid = first_invalid or expected_sequence
            expected_sequence = record.sequence_number
        if record.previous_record_hash != previous_hash:
            invalid_links += 1
            first_invalid = first_invalid or record.sequence_number
        expected_hash = calculate_record_hash(
            record_type=record.record_type, record_id=record.record_id,
            content_hash=record.content_hash, sequence_number=record.sequence_number,
            previous_record_hash=record.previous_record_hash, created_at=record.created_at,
            schema_version=record.integrity_schema_version,
        )
        if expected_hash != record.record_hash:
            invalid_links += 1
            first_invalid = first_invalid or record.sequence_number
        if content_resolver is not None:
            current = content_resolver(record)
            if current is not None and sha256_text(canonical_json(current)) != record.content_hash:
                content_mismatches += 1
                first_invalid = first_invalid or record.sequence_number
        previous_hash = record.record_hash
        expected_sequence += 1
    if expected_head is None and require_head:
        invalid_links += 1
        first_invalid = first_invalid or 1
    elif expected_head is not None:
        actual_sequence = ordered[-1].sequence_number if ordered else 0
        actual_hash = ordered[-1].record_hash if ordered else GENESIS_HASH
        if actual_sequence < expected_head.last_sequence_number:
            missing_sequences += expected_head.last_sequence_number - actual_sequence
            first_invalid = first_invalid or actual_sequence + 1
        elif actual_sequence > expected_head.last_sequence_number:
            invalid_links += 1
            first_invalid = first_invalid or expected_head.last_sequence_number + 1
        if actual_hash != expected_head.last_record_hash:
            invalid_links += 1
            first_invalid = first_invalid or max(1, actual_sequence)
    return ChainVerificationSummary(
        records_checked=len(ordered),
        chain_valid=not (content_mismatches or missing_sequences or invalid_links),
        content_mismatch_count=content_mismatches,
        missing_sequence_count=missing_sequences,
        invalid_link_count=invalid_links,
        first_invalid_sequence=first_invalid,
    )


def _default_content_resolver(db: Session, record: IntegrityLedgerRecord) -> dict | None:
    if record.record_type == "evidence":
        from app.models.evidence_file import EvidenceFile
        item = db.scalar(select(EvidenceFile).where(EvidenceFile.evidence_id == record.record_id))
        if item is None:
            return {"missing_record": True, "record_id": record.record_id}
        return {
            "evidence_id": item.evidence_id, "source_system": item.source_system,
            "file_hash": item.file_hash, "upload_timestamp": item.upload_timestamp,
            "is_encrypted": item.is_encrypted,
        }
    if record.record_type == "audit_event":
        from app.models.audit_log import AuditLog
        from app.services import audit_service
        item = db.scalar(select(AuditLog).where(AuditLog.id == int(record.record_id)))
        if item is None:
            return {"missing_record": True, "record_id": record.record_id}
        return {"id": item.id, "action": item.action, "target_type": item.target_type, "target_id": item.target_id, "timestamp": item.timestamp, "details": audit_service.resolve_audit_details(item)}
    if record.record_type == "breach_decision":
        from app.models.breach_decision import BreachDecisionRecord
        item = db.scalar(select(BreachDecisionRecord).where(BreachDecisionRecord.decision_id == record.record_id))
        if item is None:
            return {"missing_record": True, "record_id": record.record_id}
        return breach_decision_integrity_content(item)
    return None


def breach_decision_integrity_content(item: Any) -> dict:
    fields = (
        "decision_id", "incident_id", "assessment_id", "decision_version", "breach_determination",
        "assessment_method_version", "policy_version", "root_cause_ruleset_version", "taxonomy_version",
        "combination_ruleset_version", "exposure_profile_ids", "internal_only_restrictions", "input_evidence_ids",
        "affected_data_categories", "affected_subject_count", "affected_subject_count_status", "severity_inputs",
        "privacy_harm_inputs", "root_cause_summary", "severity_result", "privacy_harm_result",
        "alert_recommendation", "containment_recommendations", "customer_notification_recommendation",
        "missing_information", "uncertainties", "limitations", "human_override_present",
        "human_override_reason", "created_by", "reviewed_by", "approved_by", "created_at", "reviewed_at", "approved_at",
    )
    return {field: getattr(item, field) for field in fields}


def _scope_members(records: list[IntegrityLedgerRecord], scope_type: str, scope_id: str | None) -> list[IntegrityLedgerRecord]:
    if scope_type == "global" and scope_id is None:
        return records
    return [record for record in records if record.scope_type == scope_type and record.scope_id == scope_id]


def _failure_fingerprint(summary: ChainVerificationSummary, head: IntegrityLedgerHead | None) -> str:
    return sha256_text(canonical_json({
        "head_sequence": head.last_sequence_number if head else None,
        "head_hash": head.last_record_hash if head else None,
        "content_mismatch_count": summary.content_mismatch_count,
        "missing_sequence_count": summary.missing_sequence_count,
        "invalid_link_count": summary.invalid_link_count,
        "first_invalid_sequence": summary.first_invalid_sequence,
    }))


def verify_ledger(
    db: Session, *, scope_type: str, scope_id: str | None, executed_by: int | None,
) -> IntegrityVerificationRun:
    started = datetime.now(timezone.utc)
    _acquire_ledger_lock(db)
    records = list(db.scalars(select(IntegrityLedgerRecord).order_by(IntegrityLedgerRecord.sequence_number)).all())
    head = db.scalar(select(IntegrityLedgerHead).where(IntegrityLedgerHead.id == 1).with_for_update())
    summary = verify_chain(
        records,
        lambda record: _default_content_resolver(db, record),
        expected_head=head,
        require_head=True,
    )
    scope_records = _scope_members(records, scope_type, scope_id)
    is_global_run = scope_type == "global" and scope_id is None
    fingerprint = None if summary.chain_valid else _failure_fingerprint(summary, head)
    # The chain is always verified globally (every record in sequence), regardless
    # of scope. "verification_mode" and result_summary must be honest about that:
    # an incident-scoped run only tells you which records belong to that scope,
    # never that only the incident's records were checked.
    if summary.chain_valid:
        result_summary = (
            f"Global chain verified across {summary.records_checked} record(s); "
            f"{len(scope_records)} of them are members of this scope."
        )
    else:
        result_summary = (
            f"Global chain failed verification (checked {summary.records_checked} record(s)); "
            "no data was repaired."
        )
    run = IntegrityVerificationRun(
        verification_run_id=f"IVR-{uuid.uuid4().hex[:20].upper()}", scope_type=scope_type, scope_id=scope_id,
        records_checked=summary.records_checked, scope_records_checked=len(scope_records),
        verified_head_sequence=head.last_sequence_number if head else None,
        verified_head_hash=head.last_record_hash if head else None,
        failure_fingerprint=fingerprint, chain_valid=summary.chain_valid,
        content_mismatch_count=summary.content_mismatch_count,
        missing_sequence_count=summary.missing_sequence_count,
        invalid_link_count=summary.invalid_link_count,
        first_invalid_sequence=summary.first_invalid_sequence,
        verification_mode="global_with_scope_membership",
        result_summary=result_summary,
        started_at=started, completed_at=datetime.now(timezone.utc), executed_by=executed_by,
    )
    db.add(run)
    # Only the global verify stamps every ledger record. Incident-scoped runs
    # must not overwrite verification_status on records outside their scope,
    # since those records were not the subject of this scoped request.
    records_to_stamp = records if is_global_run else scope_records
    for record in records_to_stamp:
        record.verification_status = "verified" if summary.chain_valid else "verification_failed"
        record.last_verified_at = run.completed_at
    if not summary.chain_valid:
        _create_integrity_alert(db, run)
    db.commit()
    db.refresh(run)
    return run


def _create_integrity_alert(db: Session, run: IntegrityVerificationRun) -> None:
    from app.models.enums import Severity
    from app.models.privacy_alert import PrivacyAlert

    existing = db.scalar(select(PrivacyAlert).where(
        PrivacyAlert.integrity_failure_fingerprint == run.failure_fingerprint
    ))
    if existing is not None:
        run.integrity_alert_id = existing.alert_id
        return
    safe_summary = f"Global integrity verification failed. Review run {run.verification_run_id}."
    alert = PrivacyAlert(
        alert_id=f"ALR-INT-{uuid.uuid4().hex[:16].upper()}", alert_time=datetime.now(timezone.utc),
        source_type="integrity_verification", source_name="privacytrace-integrity", source_format="internal",
        severity=Severity.HIGH, status="new", sensitive_types=[], masked_values=[], detection_ids=[],
        evidence_id=None, linked_incident_id=None, raw_event_hash=run.failure_fingerprint or sha256_text(safe_summary),
        integrity_failure_fingerprint=run.failure_fingerprint,
        safety_status="safe", alert_summary=safe_summary,
        human_review_required=True, ingestion_source="internal_integrity", missing_metadata=[],
        correlation_recommendations=["Review the verification run; do not auto-repair ledger history."],
        evidence_strength="direct",
    )
    db.add(alert)
    db.flush()
    run.integrity_alert_id = alert.alert_id


def assert_export_allowed(
    db: Session, *, scope_type: str, scope_id: str | None, executed_by: int | None,
) -> IntegrityVerificationRun:
    run = verify_ledger(db, scope_type=scope_type, scope_id=scope_id, executed_by=executed_by)
    if not run.chain_valid:
        raise IntegrityExportBlockedError(
            f"Export blocked because integrity verification {run.verification_run_id} failed."
        )
    return run


def get_verification_run(db: Session, run_id: str) -> IntegrityVerificationRun:
    run = db.scalar(select(IntegrityVerificationRun).where(IntegrityVerificationRun.verification_run_id == run_id))
    if run is None:
        raise IntegrityNotFoundError(f"Integrity verification run not found: {run_id}")
    return run


def get_integrity_status(db: Session, *, scope_type: str, scope_id: str | None) -> tuple[list[IntegrityLedgerRecord], IntegrityVerificationRun | None]:
    stmt = select(IntegrityLedgerRecord).order_by(IntegrityLedgerRecord.sequence_number)
    if scope_id is not None:
        stmt = stmt.where(IntegrityLedgerRecord.scope_type == scope_type, IntegrityLedgerRecord.scope_id == scope_id)
    records = list(db.scalars(stmt).all())
    latest = db.scalar(select(IntegrityVerificationRun).where(
        IntegrityVerificationRun.scope_type == scope_type,
        IntegrityVerificationRun.scope_id == scope_id,
    ).order_by(IntegrityVerificationRun.started_at.desc()).limit(1))
    return records, latest


def get_record_integrity(
    db: Session, *, record_type: str, record_id: str
) -> tuple[list[IntegrityLedgerRecord], IntegrityVerificationRun | None]:
    records = list(
        db.scalars(
            select(IntegrityLedgerRecord)
            .where(
                IntegrityLedgerRecord.record_type == record_type,
                IntegrityLedgerRecord.record_id == record_id,
            )
            .order_by(IntegrityLedgerRecord.sequence_number)
        ).all()
    )
    if not records:
        raise IntegrityNotFoundError(
            f"Integrity record not found for {record_type}: {record_id}"
        )
    latest = db.scalar(
        select(IntegrityVerificationRun)
        .where(
            IntegrityVerificationRun.scope_type == records[-1].scope_type,
            IntegrityVerificationRun.scope_id == records[-1].scope_id,
        )
        .order_by(IntegrityVerificationRun.started_at.desc())
        .limit(1)
    )
    return records, latest
