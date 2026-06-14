from subprocess import CompletedProcess

import pytest

from app.models.enums import VerificationStatus
from app.models.workflow_verification import (
    ControlledRetest,
    RemediationImplementationRecord,
    RemediationTestExecution,
)
from app.services import fix_verification_service, sandbox_test_execution_service


def test_first_class_implementation_and_retest_tables_exist():
    assert RemediationImplementationRecord.__tablename__ == "remediation_implementation_records"
    assert ControlledRetest.__tablename__ == "controlled_retests"
    assert "implementation_id" in RemediationTestExecution.__table__.columns


@pytest.mark.parametrize(
    ("dimensions_match", "raw_after", "expected"),
    [
        (False, False, VerificationStatus.INCONCLUSIVE),
        (True, True, VerificationStatus.FAILED),
        (True, False, VerificationStatus.PASSED),
        (True, None, VerificationStatus.INCONCLUSIVE),
    ],
)
def test_controlled_retest_status_is_conservative(
    dimensions_match, raw_after, expected
):
    assert (
        fix_verification_service.verification_status_for_retest(
            dimensions_match=dimensions_match,
            raw_exposure_after_change=raw_after,
        )
        == expected
    )


def test_allowlisted_runner_masks_output_and_counts_leak(monkeypatch):
    monkeypatch.setattr(
        sandbox_test_execution_service.subprocess,
        "run",
        lambda *args, **kwargs: CompletedProcess(
            args=args,
            returncode=0,
            stdout="customer phone 9841234567",
            stderr="",
        ),
    )
    result = sandbox_test_execution_service.run_profile("backend_python")
    assert "9841234567" not in result["safe_output_summary"]
    assert result["raw_value_leakage_result"] > 0
    assert result["status"] == "failed"


def test_runner_rejects_arbitrary_profile():
    with pytest.raises(sandbox_test_execution_service.SandboxTestError):
        sandbox_test_execution_service.run_profile("run-any-shell-command")


def test_persisted_sandbox_run_binds_incident_from_implementation(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    impl = SimpleNamespace(
        incident_id="INC-CANONICAL",
        remediation_action_id="RA-1",
        implementation_id="IMP-1",
        workflow_status="current",
        status="completed",
        patch_proposal_id=None,
        implementation_mode="manual",
        change_hash="abc",
    )
    captured: dict[str, str] = {}

    db = MagicMock()
    db.add.side_effect = lambda row: captured.update(incident_id=row.incident_id)
    db.scalar.return_value = SimpleNamespace(remediation_action_id="RA-1")
    monkeypatch.setattr(
        sandbox_test_execution_service.remediation_lifecycle_service,
        "get_implementation",
        lambda *_a, **_k: impl,
    )
    monkeypatch.setattr(
        sandbox_test_execution_service.remediation_lifecycle_service,
        "_permission_for_action",
        lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        sandbox_test_execution_service.subprocess,
        "run",
        lambda *args, **kwargs: CompletedProcess(
            args=args, returncode=0, stdout="ok", stderr=""
        ),
    )
    with pytest.raises(
        sandbox_test_execution_service.SandboxTestError, match="does not belong"
    ):
        sandbox_test_execution_service.run_profile(
            "backend_python",
            db=db,
            incident_id="INC-FORGED",
            remediation_action_id="RA-1",
            implementation_id="IMP-1",
        )
    sandbox_test_execution_service.run_profile(
        "backend_python",
        db=db,
        incident_id=None,
        remediation_action_id="RA-1",
        implementation_id="IMP-1",
    )
    assert captured["incident_id"] == "INC-CANONICAL"
