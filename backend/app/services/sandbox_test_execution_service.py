"""Allowlisted controlled local test workspace profiles — never execute AI-generated shell strings."""

from __future__ import annotations

import subprocess
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_backend_root
from app.models.remediation_action import RemediationAction
from app.models.verified_remediation_learning import PatchProposal
from app.models.workflow_verification import RemediationImplementationRecord, RemediationTestExecution
from app.services import audit_safety_service, remediation_lifecycle_service

# Fixed profiles only. Commands are constants, not model output.
TEST_PROFILES: dict[str, dict[str, Any]] = {
    "backend_python": {
        "command": ["python", "-m", "pytest", "app/tests/test_unified_exposure_engine.py", "-q"],
        "cwd": str(get_backend_root()),
        "timeout_seconds": 120,
    },
    "privacy_regression": {
        "command": [
            "python",
            "-m",
            "pytest",
            "app/tests/test_instance_level_evaluation.py",
            "app/tests/test_input_output_safety_separation.py",
            "-q",
        ],
        "cwd": str(get_backend_root()),
        "timeout_seconds": 120,
    },
    "synthetic_request_logger_regression": {
        "command": [
            "python",
            "-m",
            "pytest",
            "fixtures/gold_standard_wallet/test_request_logger_regression.py",
            "-q",
        ],
        "cwd": str(get_backend_root()),
        "timeout_seconds": 60,
    },
    "frontend_react": {
        "command": ["npm", "test", "--", "--run"],
        "cwd": str(get_backend_root().parent / "frontend"),
        "timeout_seconds": 300,
    },
}


class SandboxTestError(ValueError):
    pass


def list_profiles() -> list[str]:
    return sorted(TEST_PROFILES)


def run_profile(
    profile_name: str,
    sandbox_workspace: str | None = None,
    *,
    db: Session | None = None,
    incident_id: str | None = None,
    remediation_action_id: str | None = None,
    patch_proposal_id: str | None = None,
    patch: PatchProposal | None = None,
    executed_by: str | None = None,
    actor_id: int | None = None,
    implementation_id: str | None = None,
) -> dict[str, Any]:
    profile = TEST_PROFILES.get(profile_name)
    if not profile:
        raise SandboxTestError(f"Unknown or non-allowlisted test profile: {profile_name}")

    implementation = None
    if db is not None:
        if not remediation_action_id or not implementation_id:
            raise SandboxTestError(
                "Persisted controlled tests require remediation_action_id and implementation_id."
            )
        implementation = remediation_lifecycle_service.get_implementation(
            db, implementation_id
        )
        if incident_id is not None and implementation.incident_id != incident_id:
            raise SandboxTestError("Implementation does not belong to the requested incident.")
        incident_id = implementation.incident_id
        if (
            implementation.remediation_action_id != remediation_action_id
            or implementation.workflow_status != "current"
            or implementation.status != "completed"
        ):
            raise SandboxTestError("Implementation does not match the current action.")
        action = db.scalar(
            select(RemediationAction).where(
                RemediationAction.remediation_action_id == remediation_action_id
            )
        )
        if action is None:
            raise SandboxTestError("Remediation action not found.")
        remediation_lifecycle_service._permission_for_action(
            db, action, actor_id=actor_id
        )
        if implementation.patch_proposal_id:
            patch = db.scalar(
                select(PatchProposal).where(
                    PatchProposal.patch_proposal_id
                    == implementation.patch_proposal_id
                )
            )
            patch_proposal_id = implementation.patch_proposal_id
        if patch is not None:
            if patch.remediation_action_id != remediation_action_id:
                raise SandboxTestError("Patch does not belong to the remediation action.")
            if sandbox_workspace and sandbox_workspace != patch.temporary_workspace:
                raise SandboxTestError("Sandbox workspace must be derived from the patch.")
            sandbox_workspace = patch.temporary_workspace

    if patch is not None and patch.post_apply_workspace_hash and sandbox_workspace:
        from pathlib import Path

        from app.services.controlled_patch_service import _hash_workspace_file

        target = Path(sandbox_workspace) / "fixtures" / "gold_standard_wallet" / "request_logger.py"
        if target.is_file():
            current = _hash_workspace_file(target)
            if current != patch.post_apply_workspace_hash:
                raise SandboxTestError(
                    "Workspace hash does not match patch post_apply_workspace_hash; "
                    "refuse test on drifted controlled local test workspace."
                )

    cwd = profile["cwd"]
    command = list(profile["command"])
    if sandbox_workspace:
        from pathlib import Path

        from app.services.controlled_patch_service import _safe_workspace_file, _sandbox_root

        lexical_ws = Path(sandbox_workspace)
        lexical_root = _sandbox_root()
        for candidate in (lexical_root, lexical_ws):
            current = Path(candidate.anchor)
            for part in candidate.parts[1:]:
                current /= part
                if current.exists() and (
                    current.is_symlink()
                    or bool(getattr(current.lstat(), "st_file_attributes", 0) & 0x400)
                ):
                    raise SandboxTestError("sandbox workspace contains a symlink or reparse point")
        ws = lexical_ws.resolve()
        root = lexical_root.resolve()
        if root not in ws.parents and ws != root:
            raise SandboxTestError("sandbox_workspace must be under remediation sandbox root")
        if profile_name != "synthetic_request_logger_regression":
            raise SandboxTestError(
                "sandbox_workspace is only permitted for synthetic_request_logger_regression"
            )
        if patch is None:
            raise SandboxTestError("sandbox test requires its controlled patch proposal")
        _safe_workspace_file(patch, "request_logger.py")
        _safe_workspace_file(patch, "test_request_logger_regression.py")
        cwd = str(ws)
        command = [
            "python",
            "-m",
            "pytest",
            "fixtures/gold_standard_wallet/test_request_logger_regression.py",
            "-q",
        ]

    started = datetime.now(UTC)
    execution_id = f"RTE-{uuid.uuid4().hex[:12].upper()}"
    row = None
    if db is not None and implementation is not None:
        row = RemediationTestExecution(
            execution_id=execution_id,
            incident_id=implementation.incident_id,
            remediation_action_id=remediation_action_id,
            patch_proposal_id=patch_proposal_id,
            implementation_id=implementation.implementation_id,
            implementation_mode=implementation.implementation_mode,
            workspace_reference_safe=sandbox_workspace,
            workspace_hash=patch.post_apply_workspace_hash if patch else implementation.change_hash,
            test_profile=profile_name,
            command_profile_version="v1",
            started_at=started,
            status="running",
            safety_status="pending",
            executed_by=executed_by,
            workflow_status="current",
        )
        db.add(row)
        db.commit()
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=profile["timeout_seconds"],
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        if row is not None:
            row.completed_at = datetime.now(UTC)
            row.status = "failed"
            row.failed_count = 1
            row.raw_leakage_count = 0
            row.safe_output_summary = "Allowlisted test profile timed out."
            row.safety_status = "ok"
            db.commit()
            if implementation is not None and implementation.implementation_mode == "controlled_patch":
                from app.services import controlled_rollback_service

                controlled_rollback_service.maybe_auto_rollback_controlled_patch(
                    db,
                    implementation=implementation,
                    trigger=controlled_rollback_service.TRIGGER_TEST_FAILED,
                    trigger_reference=execution_id,
                    actor_id=actor_id,
                )
        raise SandboxTestError("Allowlisted test profile timed out.") from exc
    ended = datetime.now(UTC)
    stdout = (completed.stdout or "")[-4000:]
    stderr = (completed.stderr or "")[-2000:]
    combined = f"{stdout}\n{stderr}"
    violations = audit_safety_service.scan_text_for_sensitive(combined)
    raw_leak_count = len(set(violations))
    safe_summary = audit_safety_service.mask_sensitive_text(combined).strip()[-2000:]
    passed = completed.returncode == 0 and raw_leak_count == 0
    result = {
        "execution_id": execution_id,
        "profile": profile_name,
        "started_at": started.isoformat(),
        "ended_at": ended.isoformat(),
        "exit_code": completed.returncode,
        "passed": passed,
        "status": "passed" if passed else "failed",
        "safe_output_summary": safe_summary,
        "safe_error_summary": None,
        "raw_value_leakage_result": raw_leak_count,
        "network_policy": "default_host_only",
        "ai_generated_command": False,
    }

    if row is not None:
        row.completed_at = ended
        row.exit_code = completed.returncode
        row.status = result["status"]
        row.test_count = 1
        row.passed_count = 1 if passed else 0
        row.failed_count = 0 if passed else 1
        row.raw_leakage_count = raw_leak_count
        row.safe_output_summary = safe_summary
        row.safety_status = "ok" if raw_leak_count == 0 else "raw_leak_detected"
        db.commit()
        if (
            not passed
            and implementation is not None
            and implementation.implementation_mode == "controlled_patch"
        ):
            from app.services import controlled_rollback_service

            rollback = controlled_rollback_service.maybe_auto_rollback_controlled_patch(
                db,
                implementation=implementation,
                trigger=controlled_rollback_service.TRIGGER_TEST_FAILED,
                trigger_reference=execution_id,
                actor_id=actor_id,
            )
            if rollback is not None:
                result["rollback_execution_id"] = rollback.rollback_execution_id
                result["rollback_status"] = rollback.status
                result["rollback_verification"] = rollback.verification_result

    return result
