"""Controlled-sandbox rollback ledger — never production / deploy / git push."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.rollback_execution import RollbackExecution
from app.models.verified_remediation_learning import PatchProposal
from app.models.workflow_verification import RemediationImplementationRecord
from app.services import audit_service, controlled_patch_service

MAX_AUTOMATIC_ROLLBACK_RETRIES = 1

TRIGGER_TEST_FAILED = "test_execution_failed"
TRIGGER_RETEST_FAILED = "controlled_retest_failed"
TRIGGER_FIX_VERIFICATION_FAILED = "fix_verification_failed"
TRIGGER_APPLY_INTERRUPTED = "apply_interrupted"
TRIGGER_HASH_MISMATCH = "post_apply_hash_mismatch"
TRIGGER_HUMAN = "human_requested"
TRIGGER_STARTUP_RECOVERY = "startup_incomplete_recovery"

MODE_AUTOMATIC = "controlled_automatic"
MODE_HUMAN = "human_recorded"


class ControlledRollbackError(ValueError):
    pass


def _find_implementation(db: Session, patch: PatchProposal) -> RemediationImplementationRecord | None:
    return db.scalar(
        select(RemediationImplementationRecord).where(
            RemediationImplementationRecord.patch_proposal_id == patch.patch_proposal_id,
            RemediationImplementationRecord.workflow_status == "current",
        ).order_by(RemediationImplementationRecord.id.desc())
    )


def get_or_create_pending(
    db: Session,
    *,
    patch: PatchProposal,
    trigger: str,
    trigger_reference: str,
    performed_mode: str,
    actor_label: str,
    implementation_id: str | None = None,
) -> RollbackExecution:
    q = select(RollbackExecution).where(
        RollbackExecution.patch_proposal_id == patch.patch_proposal_id,
        RollbackExecution.trigger == trigger,
        RollbackExecution.trigger_reference == (trigger_reference or ""),
    )
    if implementation_id is not None:
        q = q.where(RollbackExecution.implementation_id == implementation_id)
    existing = db.scalar(q)
    if existing is not None:
        return existing
    row = RollbackExecution(
        rollback_execution_id=f"RBX-{uuid.uuid4().hex[:12].upper()}",
        incident_id=patch.incident_id,
        implementation_id=implementation_id,
        patch_proposal_id=patch.patch_proposal_id,
        baseline_snapshot_ref=patch.base_source_hash or "",
        expected_hashes={"base_source_hash": patch.base_source_hash},
        restored_hashes={},
        trigger=trigger,
        trigger_reference=trigger_reference or "",
        status="pending",
        performed_mode=performed_mode,
        actor_label=actor_label,
        generation="v1",
    )
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        existing = db.scalar(q)
        if existing is None:
            raise
        return existing
    return row


def _record_rolled_back_learning(
    db: Session, patch: PatchProposal, rollback: RollbackExecution
) -> None:
    """Failed/rolled-back attempts are ranking penalties, never success exemplars."""
    from app.models.remediation_action import RemediationAction
    from app.models.remediation_diagnosis import RemediationDiagnosis
    from app.models.verified_remediation_learning import VerifiedRemediationCase
    from app.services import verified_outcome_learning_service

    existing = db.scalar(
        select(VerifiedRemediationCase).where(
            VerifiedRemediationCase.patch_proposal_id == patch.patch_proposal_id,
            VerifiedRemediationCase.verification_result == "rolled_back",
        )
    )
    if existing is not None:
        return
    action = None
    if patch.remediation_action_id:
        action = db.scalar(
            select(RemediationAction).where(
                RemediationAction.remediation_action_id == patch.remediation_action_id
            )
        )
    diagnosis = db.scalar(
        select(RemediationDiagnosis).where(RemediationDiagnosis.diagnosis_id == patch.diagnosis_id)
    )
    primary = (diagnosis.primary_remediation if diagnosis else None) or {}
    rtype = primary.get("remediation_type")
    fp = verified_outcome_learning_service.remediation_fingerprint(
        remediation_type=rtype,
        root_cause_category=primary.get("root_cause_category"),
        sensitive_type=primary.get("sensitive_type"),
        exposure_location=primary.get("exposure_location"),
        affected_component=(diagnosis.affected_component if diagnosis else None),
        implementation_mode="controlled_patch",
    )
    db.add(
        VerifiedRemediationCase(
            verified_case_id=f"VRC-RB-{rollback.rollback_execution_id[-12:]}",
            incident_id=patch.incident_id,
            diagnosis_id=patch.diagnosis_id,
            remediation_action_id=patch.remediation_action_id,
            patch_proposal_id=patch.patch_proposal_id,
            remediation_type=rtype,
            remediation_fingerprint=fp or getattr(action, "remediation_fingerprint", None),
            affected_component=diagnosis.affected_component if diagnosis else None,
            implementation_mode="controlled_patch",
            tests_passed=False,
            verification_result="rolled_back",
            eligible_for_learning=False,
            eligibility_reason="Rolled-back controlled patch is not a success exemplar.",
            policy_version="playbook-v1",
            semantics_version="v2",
            limitations=["Automatic sandbox rollback; human review still required."],
            workflow_status="current",
        )
    )


def execute_controlled_rollback(
    db: Session,
    *,
    patch_proposal_id: str,
    trigger: str,
    trigger_reference: str = "",
    performed_mode: str = MODE_AUTOMATIC,
    actor_id: int | None = None,
    actor_email: str | None = None,
    actor_role: str | None = None,
    force_incomplete: bool = False,
    commit: bool = True,
) -> RollbackExecution:
    """Restore sandbox from PreChangeSnapshot (.orig + base_source_hash) and verify hashes."""
    patch = controlled_patch_service.get_patch(db, patch_proposal_id)
    if not patch.base_source_hash:
        raise ControlledRollbackError("Pre-change snapshot hash missing; cannot rollback.")

    implementation = _find_implementation(db, patch)
    implementation_id = implementation.implementation_id if implementation else None
    if implementation is not None and implementation.implementation_mode != "controlled_patch":
        # Human/external: record recommendation only — do not claim automatic restore.
        row = get_or_create_pending(
            db,
            patch=patch,
            trigger=trigger,
            trigger_reference=trigger_reference,
            performed_mode=MODE_HUMAN,
            actor_label=actor_email or "human",
            implementation_id=implementation_id,
        )
        if row.status in {"succeeded", "failed", "inconclusive"}:
            return row
        row.status = "inconclusive"
        row.performed_mode = MODE_HUMAN
        row.verification_result = "inconclusive"
        row.rollback_verified = False
        row.failure_reason_safe = "ROLLBACK REQUIRED — human-governed restore; PrivacyTrace did not modify production."
        row.completed_at = datetime.now(UTC)
        db.add(row)
        if commit:
            db.commit()
            db.refresh(row)
        return row

    actor_label = "system" if performed_mode == MODE_AUTOMATIC else (actor_email or "human")
    row = get_or_create_pending(
        db,
        patch=patch,
        trigger=trigger,
        trigger_reference=trigger_reference,
        performed_mode=performed_mode,
        actor_label=actor_label,
        implementation_id=implementation_id,
    )
    if row.status == "succeeded" and row.rollback_verified:
        return row
    if row.status == "failed" and int(row.retry_count or 0) >= MAX_AUTOMATIC_ROLLBACK_RETRIES:
        return row

    row.status = "running"
    row.started_at = datetime.now(UTC)
    row.retry_count = int(row.retry_count or 0) + (1 if row.verification_result == "failed" else 0)
    db.add(row)
    db.flush()

    try:
        restored = controlled_patch_service.restore_sandbox_from_baseline(
            db,
            patch,
            force_incomplete=force_incomplete,
            actor_id=actor_id,
            actor_email=actor_email,
            actor_role=actor_role or ("system" if performed_mode == MODE_AUTOMATIC else None),
            performed_mode=performed_mode,
        )
        current_hash = restored.get("restored_hash")
        expected = patch.base_source_hash
        row.restored_hashes = {"request_logger.py": current_hash}
        row.expected_hashes = {"request_logger.py": expected, "base_source_hash": expected}
        if current_hash and expected and current_hash == expected:
            row.status = "succeeded"
            row.rollback_verified = True
            row.verification_result = "passed"
            row.failure_reason_safe = None
            if implementation is not None:
                implementation.status = "rolled_back"
                db.add(implementation)
            _record_rolled_back_learning(db, patch, row)
        else:
            row.status = "failed"
            row.rollback_verified = False
            row.verification_result = "failed"
            row.failure_reason_safe = "Rollback hash verification failed; workspace marked unsafe."
            patch.recovery_required = True
            patch.workspace_integrity_status = "unsafe"
            patch.last_known_state = "rollback_verification_failed"
            db.add(patch)
    except controlled_patch_service.ControlledPatchError as exc:
        row.status = "failed"
        row.rollback_verified = False
        row.verification_result = "failed"
        row.failure_reason_safe = str(exc)[:500]
        patch.recovery_required = True
        patch.workspace_integrity_status = "unsafe"
        db.add(patch)
    except Exception as exc:  # pragma: no cover - defensive
        row.status = "failed"
        row.rollback_verified = False
        row.verification_result = "failed"
        row.failure_reason_safe = f"Rollback aborted: {type(exc).__name__}"
        patch.recovery_required = True
        db.add(patch)

    row.completed_at = datetime.now(UTC)
    db.add(row)
    audit_service.log_action(
        db,
        action="controlled_rollback_execution",
        target_type="rollback_execution",
        target_id=row.rollback_execution_id,
        details={
            "incident_id": row.incident_id,
            "patch_proposal_id": patch.patch_proposal_id,
            "trigger": trigger,
            "status": row.status,
            "verification_result": row.verification_result,
            "performed_mode": row.performed_mode,
            "production_modified": False,
        },
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
    )
    if commit:
        db.commit()
        db.refresh(row)
    return row


def maybe_auto_rollback_controlled_patch(
    db: Session,
    *,
    implementation: RemediationImplementationRecord | None,
    trigger: str,
    trigger_reference: str,
    actor_id: int | None = None,
) -> RollbackExecution | None:
    if implementation is None or implementation.implementation_mode != "controlled_patch":
        return None
    if not implementation.patch_proposal_id:
        return None
    return execute_controlled_rollback(
        db,
        patch_proposal_id=implementation.patch_proposal_id,
        trigger=trigger,
        trigger_reference=trigger_reference,
        performed_mode=MODE_AUTOMATIC,
        actor_id=actor_id,
        actor_role="system",
        commit=True,
    )


def recover_incomplete_patches(db: Session) -> list[dict[str, Any]]:
    """Startup/resume: restore incomplete controlled applies once (bounded)."""
    candidates = list(
        db.scalars(
            select(PatchProposal).where(
                PatchProposal.workflow_status == "current",
                PatchProposal.recovery_required.is_(True),
            ).limit(20)
        ).all()
    )
    interrupted = list(
        db.scalars(
            select(PatchProposal).where(
                PatchProposal.workflow_status == "current",
                PatchProposal.last_known_state.in_(["apply_interrupted", "applying"]),
            ).limit(20)
        ).all()
    )
    seen: set[str] = set()
    results: list[dict[str, Any]] = []
    for patch in [*candidates, *interrupted]:
        if patch.patch_proposal_id in seen:
            continue
        seen.add(patch.patch_proposal_id)
        try:
            row = execute_controlled_rollback(
                db,
                patch_proposal_id=patch.patch_proposal_id,
                trigger=TRIGGER_STARTUP_RECOVERY,
                trigger_reference=patch.patch_proposal_id,
                performed_mode=MODE_AUTOMATIC,
                force_incomplete=True,
                commit=True,
            )
            results.append(
                {
                    "patch_proposal_id": patch.patch_proposal_id,
                    "rollback_execution_id": row.rollback_execution_id,
                    "status": row.status,
                    "verification_result": row.verification_result,
                }
            )
        except Exception as exc:  # pragma: no cover
            results.append(
                {
                    "patch_proposal_id": patch.patch_proposal_id,
                    "status": "failed",
                    "error": type(exc).__name__,
                }
            )
    return results
