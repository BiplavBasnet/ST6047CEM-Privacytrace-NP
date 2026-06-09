"""Controlled patch generation — Option B gold-fixture controlled local test workspace.

Scope (Option B): allowlisted gold-standard wallet fixture only. This is a
proof-of-concept for a controlled local test workspace — not a general
multi-repo production patch engine and not a secure process/network sandbox.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_backend_root, get_settings
from app.models.remediation_action import RemediationAction
from app.models.remediation_diagnosis import RemediationDiagnosis
from app.models.verified_remediation_learning import PatchProposal
from app.services import (
    audit_service,
    patch_safety_service,
    remediation_ai_safety_service,
    remediation_repository_safety_service,
    workflow_provenance_service,
)
from app.services.ai_remediation_diagnosis_service import DiagnosisGateError, DiagnosisStateError
from app.services.workflow_provenance_service import WorkflowProvenanceError

GOLD_REL = Path("fixtures") / "gold_standard_wallet" / "request_logger.py"
GOLD_FIXED_REL = Path("fixtures") / "gold_standard_wallet" / "request_logger_fixed.py"


class ControlledPatchError(Exception):
    pass


def _assert_patch_permission(
    db: Session,
    *,
    diagnosis: RemediationDiagnosis,
    action: RemediationAction,
    actor_id: int | None,
    require_actor: bool,
) -> None:
    try:
        workflow_provenance_service.assert_current_governed_remediation_permission(
            db,
            diagnosis.incident_id,
            actor_id=actor_id,
            require_active_human_actor=require_actor,
            root_cause_analysis_id=diagnosis.root_cause_analysis_id,
            root_cause_analysis_version=diagnosis.root_cause_analysis_version,
            evidence_snapshot_hash=diagnosis.evidence_snapshot_hash,
            review_decision_id=diagnosis.review_decision_id,
            diagnosis_id=diagnosis.diagnosis_id,
            remediation_action_id=action.remediation_action_id,
        )
    except WorkflowProvenanceError as exc:
        raise ControlledPatchError(str(exc)) from exc


def _sandbox_root() -> Path:
    settings = get_settings()
    root = Path(settings.remediation_sandbox_root)
    if not root.is_absolute():
        root = get_backend_root() / root
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        if current.exists() and _is_reparse(current):
            raise ControlledPatchError("Sandbox root cannot traverse a symlink or reparse point.")
    root.mkdir(parents=True, exist_ok=True)
    return root


def _hash_workspace_file(path: Path) -> str:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    return f"sha256:{digest}"


def _canonical_lf_bytes(raw: bytes) -> bytes:
    """Sandbox integrity hashes raw bytes; never mix CRLF checkout bytes with LF writes."""
    return raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _write_sandbox_bytes(path: Path, raw: bytes) -> None:
    path.write_bytes(_canonical_lf_bytes(raw))


def _is_reparse(path: Path) -> bool:
    try:
        return path.is_symlink() or bool(
            getattr(path.lstat(), "st_file_attributes", 0) & 0x400
        )
    except OSError:
        return False


def _safe_workspace_file(row: PatchProposal, name: str) -> Path:
    lexical_root = _sandbox_root()
    root = lexical_root.resolve()
    workspace = Path(row.temporary_workspace)
    try:
        lexical_relative = workspace.relative_to(lexical_root)
    except ValueError as exc:
        raise ControlledPatchError("Sandbox workspace escapes the configured root.") from exc
    current = lexical_root
    for part in lexical_relative.parts:
        current /= part
        if current.exists() and _is_reparse(current):
            raise ControlledPatchError("Sandbox workspace cannot traverse a symlink or reparse point.")
    try:
        resolved_workspace = workspace.resolve(strict=True)
        resolved_workspace.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ControlledPatchError("Sandbox workspace escapes the configured root.") from exc
    target = resolved_workspace / "fixtures" / "gold_standard_wallet" / name
    current = resolved_workspace
    for part in target.relative_to(resolved_workspace).parts:
        current /= part
        if current.exists() and _is_reparse(current):
            raise ControlledPatchError("Sandbox target cannot traverse a symlink or reparse point.")
    try:
        target.resolve(strict=target.exists()).relative_to(resolved_workspace)
    except (OSError, ValueError) as exc:
        raise ControlledPatchError("Sandbox target escapes its workspace.") from exc
    return target


def _recovery_error(db: Session, row: PatchProposal, message: str) -> None:
    row.status = "recovery_required"
    row.last_known_state = "integrity_drift"
    row.workspace_integrity_status = "failed"
    row.recovery_required = True
    db.add(row)
    db.commit()
    raise ControlledPatchError(message)


def _build_unified_diff(old_text: str, new_text: str, rel_path: str) -> str:
    import difflib

    return "".join(
        difflib.unified_diff(
            old_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
        )
    )


def _gold_source_paths() -> tuple[Path, Path]:
    try:
        return (
            remediation_repository_safety_service.resolve_safe_repo_path(str(GOLD_REL)),
            remediation_repository_safety_service.resolve_safe_repo_path(str(GOLD_FIXED_REL)),
        )
    except ValueError as exc:
        raise ControlledPatchError("Allowlisted controlled patch fixture is unavailable.") from exc


def _require_remediation_action(db: Session, remediation_action_id: str | None) -> RemediationAction:
    if not remediation_action_id:
        raise ControlledPatchError(
            "Controlled patch generation requires a non-null remediation_action_id "
            "(accept a diagnosis first)."
        )
    action = db.scalar(
        select(RemediationAction).where(
            RemediationAction.remediation_action_id == remediation_action_id
        )
    )
    if action is None:
        raise ControlledPatchError(f"Remediation action not found: {remediation_action_id}")
    return action


def generate_real_patch_proposal(
    db: Session,
    diagnosis: RemediationDiagnosis,
    *,
    remediation_action_id: str | None,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> PatchProposal:
    """Generate an allowlisted unified diff in a controlled local test workspace (Option B)."""
    if diagnosis.status not in {"accepted", "accepted_with_edits"}:
        raise DiagnosisStateError(
            "Controlled patch generation requires an accepted human remediation review."
        )
    if not diagnosis.exact_source_location_known:
        raise ControlledPatchError(
            "Exact source-level patch is not available without established source localisation."
        )
    action = _require_remediation_action(db, remediation_action_id)
    _assert_patch_permission(
        db,
        diagnosis=diagnosis,
        action=action,
        actor_id=actor_id,
        require_actor=True,
    )

    vulnerable, fixed = _gold_source_paths()
    # Only allow gold-standard relative path (or diagnosis file matching it).
    diag_file = (diagnosis.affected_file or "").replace("\\", "/")
    allowed = str(GOLD_REL).replace("\\", "/")
    if diag_file != allowed:
        raise ControlledPatchError(
            f"Allowlisted Controlled Patch PoC only supports the exact file {allowed}."
        )
    primary = diagnosis.primary_remediation or {}
    if primary.get("remediation_type") not in {"request_header_redaction", "other"}:
        raise ControlledPatchError("Diagnosis does not match the allowlisted request-logging PoC.")

    old_text = vulnerable.read_text(encoding="utf-8")
    new_text = fixed.read_text(encoding="utf-8")
    rel = allowed
    diff_text = _build_unified_diff(old_text, new_text, rel)
    if not diff_text.strip():
        raise ControlledPatchError("No diff produced between vulnerable and fixed fixtures.")

    patch_safety_service.validate_patch_payload(file_paths=[rel], diff_text=diff_text)

    patch_id = f"PATCH-{uuid.uuid4().hex[:10].upper()}"
    workspace = _sandbox_root() / patch_id
    workspace.mkdir(parents=True, exist_ok=True)
    target_dir = workspace / "fixtures" / "gold_standard_wallet"
    target_dir.mkdir(parents=True, exist_ok=True)
    # Snapshot LF bytes only. Git on Windows often checks out CRLF; hashing those
    # while apply writes LF is the apply/rollback/recovery mismatch family.
    baseline = _canonical_lf_bytes(vulnerable.read_bytes())
    _write_sandbox_bytes(target_dir / "request_logger.py", baseline)
    _write_sandbox_bytes(target_dir / "request_logger.py.orig", baseline)
    test_src = get_backend_root() / "fixtures" / "gold_standard_wallet" / "test_request_logger_regression.py"
    if test_src.is_file():
        _write_sandbox_bytes(target_dir / "test_request_logger_regression.py", test_src.read_bytes())

    (workspace / "PROPOSED.diff").write_text(diff_text, encoding="utf-8", newline="\n")
    digest = hashlib.sha256(diff_text.encode("utf-8")).hexdigest()
    branch = f"sandbox/{patch_id.lower()}"
    base_hash = _hash_workspace_file(target_dir / "request_logger.py")

    row = PatchProposal(
        patch_proposal_id=patch_id,
        remediation_action_id=action.remediation_action_id,
        diagnosis_id=diagnosis.diagnosis_id,
        root_cause_analysis_id=diagnosis.root_cause_analysis_id,
        incident_id=diagnosis.incident_id,
        repository_reference_safe="backend/fixtures/gold_standard_wallet",
        base_commit="fixture-local",
        temporary_workspace=str(workspace),
        temporary_branch=branch,
        affected_files=[rel],
        patch_hash=f"sha256:{digest}",
        safe_diff=diff_text,
        safety_result="passed",
        status="awaiting_human_review",
        human_approval_status="pending",
        rollback_status="not_applied",
        base_source_hash=base_hash,
        recovery_required=False,
        workflow_status="current",
    )
    db.add(row)
    audit_service.log_action(
        db,
        action="controlled_patch_generated",
        target_type="patch_proposal",
        target_id=patch_id,
        details={
            "diagnosis_id": diagnosis.diagnosis_id,
            "remediation_action_id": action.remediation_action_id,
            "affected_files": [rel],
            "production_modified": False,
            "remote_push": False,
            "workspace": str(workspace),
            "option_b_gold_fixture_only": True,
        },
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
    )
    db.commit()
    db.refresh(row)
    return row


def generate_draft_patch(
    db: Session,
    diagnosis: RemediationDiagnosis,
    *,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> dict[str, Any]:
    action = db.scalar(
        select(RemediationAction).where(RemediationAction.diagnosis_id == diagnosis.diagnosis_id)
    )
    row = generate_real_patch_proposal(
        db,
        diagnosis,
        remediation_action_id=action.remediation_action_id if action else None,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
    )
    return {
        "patch_id": row.patch_proposal_id,
        "patch_proposal_id": row.patch_proposal_id,
        "diagnosis_id": row.diagnosis_id,
        "remediation_action_id": row.remediation_action_id,
        "sandbox_workspace": row.temporary_workspace,
        "safe_diff": row.safe_diff,
        "affected_files": row.affected_files,
        "status": row.status,
        "content_hash": row.patch_hash,
        "human_approval_required": True,
        "applied_to_production": False,
        "created_at": datetime.now(UTC).isoformat(),
        "message": (
            "Allowlisted Controlled Patch PoC diff generated in a local test workspace. "
            "Human approval is required before apply; production modification is impossible."
        ),
    }


def require_accepted_diagnosis(db: Session, diagnosis_id: str) -> RemediationDiagnosis:
    from app.services import ai_remediation_diagnosis_service as diag

    row = diag.get_diagnosis(db, diagnosis_id)
    if row.status not in {"accepted", "accepted_with_edits"}:
        raise DiagnosisGateError("Diagnosis must be accepted before patch generation.")
    action = db.scalar(
        select(RemediationAction).where(RemediationAction.diagnosis_id == row.diagnosis_id)
    )
    if action is None:
        raise DiagnosisGateError("Diagnosis has no canonical remediation action.")
    try:
        _assert_patch_permission(
            db,
            diagnosis=row,
            action=action,
            actor_id=None,
            require_actor=False,
        )
    except ControlledPatchError as exc:
        raise DiagnosisGateError(str(exc)) from exc
    remediation_ai_safety_service.assert_no_raw_sensitive(
        {"primary": row.primary_remediation, "proposed": row.proposed_change}
    )
    return row


def get_patch(db: Session, patch_proposal_id: str) -> PatchProposal:
    row = db.scalar(
        select(PatchProposal).where(PatchProposal.patch_proposal_id == patch_proposal_id)
    )
    if not row:
        raise ControlledPatchError(f"Patch proposal not found: {patch_proposal_id}")
    return row


def approve_patch_for_sandbox(
    db: Session,
    patch_proposal_id: str,
    *,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> PatchProposal:
    row = get_patch(db, patch_proposal_id)
    diagnosis = require_accepted_diagnosis(db, row.diagnosis_id)
    action = _require_remediation_action(db, row.remediation_action_id)
    _assert_patch_permission(
        db,
        diagnosis=diagnosis,
        action=action,
        actor_id=actor_id,
        require_actor=True,
    )
    if row.workflow_status != "current":
        raise ControlledPatchError("Patch proposal is stale and cannot be approved.")
    if row.status not in {"awaiting_human_review", "generated"}:
        raise ControlledPatchError(f"Cannot approve patch from status={row.status}")
    if row.safety_result != "passed":
        raise ControlledPatchError("Cannot approve a patch that failed safety checks.")
    row.status = "approved_for_sandbox"
    row.human_approval_status = "approved"
    row.approved_by = actor_id
    row.approved_at = datetime.now(UTC)
    db.add(row)
    audit_service.log_action(
        db,
        action="controlled_patch_human_approved",
        target_type="patch_proposal",
        target_id=row.patch_proposal_id,
        details={"status": row.status},
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
    )
    db.commit()
    db.refresh(row)
    return row


def apply_patch_to_sandbox(
    db: Session,
    patch_proposal_id: str,
    *,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> PatchProposal:
    row = get_patch(db, patch_proposal_id)
    diagnosis = require_accepted_diagnosis(db, row.diagnosis_id)
    action = _require_remediation_action(db, row.remediation_action_id)
    _assert_patch_permission(
        db,
        diagnosis=diagnosis,
        action=action,
        actor_id=actor_id,
        require_actor=True,
    )
    if row.workflow_status != "current":
        raise ControlledPatchError("Patch proposal is stale and cannot be applied.")
    if row.status != "approved_for_sandbox":
        raise ControlledPatchError("Sandbox apply requires human approval for sandbox testing.")
    if row.human_approval_status != "approved":
        raise ControlledPatchError("AI cannot approve patches; human approval required.")

    workspace = Path(row.temporary_workspace)
    target = _safe_workspace_file(row, "request_logger.py")
    if not target.is_file():
        raise ControlledPatchError("Sandbox target file missing.")

    current_hash = _hash_workspace_file(target)
    if not row.base_source_hash or current_hash != row.base_source_hash:
        _recovery_error(db, row, "Sandbox base hash changed before apply.")
    patch_hash = f"sha256:{hashlib.sha256(row.safe_diff.encode('utf-8')).hexdigest()}"
    if patch_hash != row.patch_hash:
        _recovery_error(db, row, "Persisted patch diff hash does not match its proposal.")

    # Apply fixed content (validated allowlisted path only).
    _, fixed = _gold_source_paths()
    # Hash the LF bytes we write. Windows checkouts of the fixture are often CRLF,
    # so hashing the on-disk file would disagree with write_text(newline="\n").
    new_text = fixed.read_text(encoding="utf-8").replace("\r\n", "\n")
    expected_payload = _canonical_lf_bytes(new_text.encode("utf-8"))
    expected_post_hash = f"sha256:{hashlib.sha256(expected_payload).hexdigest()}"
    canonical_diff = _build_unified_diff(
        target.read_text(encoding="utf-8"), new_text, str(GOLD_REL).replace("\\", "/")
    )
    if list(row.affected_files or []) != [str(GOLD_REL).replace("\\", "/")]:
        _recovery_error(db, row, "Patch affected-file scope changed after approval.")
    if row.safe_diff != canonical_diff:
        _recovery_error(db, row, "Patch diff no longer matches the canonical approved change.")
    patch_safety_service.validate_patch_payload(
        file_paths=list(row.affected_files or []),
        diff_text=row.safe_diff,
    )
    row.status = "applying"
    row.last_known_state = "applying"
    row.recovery_required = False
    db.add(row)
    db.flush()

    try:
        _write_sandbox_bytes(target, expected_payload)
        row.status = "applied_to_sandbox"
        row.applied_at = datetime.now(UTC)
        row.rollback_status = "available"
        row.post_apply_workspace_hash = _hash_workspace_file(target)
        row.pre_test_workspace_hash = row.post_apply_workspace_hash
        if row.post_apply_workspace_hash != expected_post_hash:
            _recovery_error(db, row, "Sandbox post-apply hash does not match approved content.")
        row.workspace_integrity_status = "ok"
        row.last_known_state = "applied"
        row.recovery_required = False
    except ControlledPatchError:
        raise
    except Exception:
        row.status = "applying"
        row.last_known_state = "apply_interrupted"
        row.recovery_required = True
        db.add(row)
        db.commit()
        raise

    db.add(row)
    audit_service.log_action(
        db,
        action="controlled_patch_applied_sandbox",
        target_type="patch_proposal",
        target_id=row.patch_proposal_id,
        details={
            "workspace": str(workspace),
            "production_modified": False,
            "remote_push": False,
            "file_changed": str(target),
            "post_apply_workspace_hash": row.post_apply_workspace_hash,
            "pre_change_snapshot": row.base_source_hash,
        },
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
    )
    from app.services import remediation_lifecycle_service

    remediation_lifecycle_service.record_implementation(
        db,
        remediation_action_id=action.remediation_action_id,
        implementation_mode="controlled_patch",
        implementation_summary="Approved patch applied to the controlled local test workspace.",
        patch_proposal_id=row.patch_proposal_id,
        actor_id=actor_id,
        commit=False,
    )
    db.commit()
    db.refresh(row)
    return row


def restore_sandbox_from_baseline(
    db: Session,
    row: PatchProposal,
    *,
    force_incomplete: bool = False,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
    performed_mode: str = "controlled_automatic",
) -> dict[str, str | None]:
    """Restore allowlisted sandbox file from PreChangeSnapshot (.orig). Hash-verify after write."""
    workspace = Path(row.temporary_workspace)
    target = _safe_workspace_file(row, "request_logger.py")
    orig = _safe_workspace_file(row, "request_logger.py.orig")
    if not orig.is_file():
        raise ControlledPatchError("Original sandbox snapshot missing; cannot rollback.")
    if not row.base_source_hash or _hash_workspace_file(orig) != row.base_source_hash:
        _recovery_error(db, row, "Original sandbox snapshot hash does not match the approved base.")
    if not force_incomplete:
        if row.post_apply_workspace_hash and target.is_file():
            current = _hash_workspace_file(target)
            # Allow restore when already at baseline (idempotent) or still at post-apply.
            if current not in {row.post_apply_workspace_hash, row.base_source_hash}:
                _recovery_error(
                    db, row, "Sandbox content drifted after apply; automatic rollback blocked."
                )
    target.write_bytes(orig.read_bytes())
    restored_hash = _hash_workspace_file(target)
    if restored_hash != row.base_source_hash:
        _recovery_error(db, row, "Rollback did not restore the approved base hash.")
    row.status = "rolled_back"
    row.rollback_status = "rolled_back"
    row.recovery_required = False
    row.workspace_integrity_status = "ok"
    row.last_known_state = "rolled_back"
    row.post_apply_workspace_hash = restored_hash
    db.add(row)
    audit_service.log_action(
        db,
        action="controlled_patch_rolled_back",
        target_type="patch_proposal",
        target_id=row.patch_proposal_id,
        details={
            "workspace": str(workspace),
            "performed_mode": performed_mode,
            "restored_hash": restored_hash,
            "production_modified": False,
        },
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
    )
    db.flush()
    return {"restored_hash": restored_hash}


def rollback_sandbox_patch(
    db: Session,
    patch_proposal_id: str,
    *,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> PatchProposal:
    row = get_patch(db, patch_proposal_id)
    diagnosis = require_accepted_diagnosis(db, row.diagnosis_id)
    action = _require_remediation_action(db, row.remediation_action_id)
    _assert_patch_permission(
        db,
        diagnosis=diagnosis,
        action=action,
        actor_id=actor_id,
        require_actor=True,
    )
    from app.services import controlled_rollback_service

    controlled_rollback_service.execute_controlled_rollback(
        db,
        patch_proposal_id=patch_proposal_id,
        trigger=controlled_rollback_service.TRIGGER_HUMAN,
        trigger_reference=f"human:{actor_id or 0}",
        performed_mode=controlled_rollback_service.MODE_HUMAN,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
        commit=True,
    )
    db.refresh(row)
    return row

