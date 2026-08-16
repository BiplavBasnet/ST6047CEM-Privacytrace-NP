import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import ControlledRemediationLifecyclePanel from "../components/incident/ControlledRemediationLifecyclePanel";
import type { IncidentWorkspaceData } from "../pages/incidents/types";

describe("ControlledRemediationLifecyclePanel persisted resume", () => {
  it("resumes a hydrated current-complete chain and enables exact verification", () => {
    const data = {
      incident: { incident_id: "INC-1" },
      workflow: {
        workflow_chain_status: "current",
        remediation_action_id: "ACT-1",
        blocked_reasons: [],
      },
      remediationActions: [{ remediation_action_id: "ACT-1", affected_component: "request_logger" }],
      currentDiagnosis: {
        affected_service: "wallet-api",
        affected_endpoint: "/payments",
        primary_remediation: { exposure_location: "request_body", affected_component: "request_logger" },
      },
      remediationLifecycle: {
        workflow_chain_status: "current_complete",
        implementation: {
          implementation_id: "IMP-1", remediation_action_id: "ACT-1", implementation_summary: "Applied reviewed redaction.",
          implementation_mode: "manual", status: "completed", patch_proposal_id: null,
        },
        test_execution: { execution_id: "TEST-1", status: "passed", workflow_status: "current" },
        controlled_retest: {
          controlled_retest_id: "CRT-1", status: "completed", workflow_status: "current",
          dimensions_match: true, raw_exposure_after_change: false,
        },
        verification_result: null,
        learning_eligible: false,
      },
    } as unknown as IncidentWorkspaceData;

    render(<ControlledRemediationLifecyclePanel data={data} canOperate onRefresh={vi.fn()} />);
    expect(screen.getByText(/Test execution TEST-1: passed/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Verify current controlled retest" })).toBeEnabled();
  });

  it("shows rollback banner and does not show success green after failed rollback path", () => {
    const data = {
      incident: { incident_id: "INC-2" },
      workflow: { workflow_chain_status: "current", remediation_action_id: "ACT-1", blocked_reasons: [] },
      remediationActions: [{ remediation_action_id: "ACT-1", affected_component: "request_logger" }],
      currentDiagnosis: {
        affected_service: "wallet-api",
        affected_endpoint: "/payments",
        primary_remediation: { exposure_location: "request_body", affected_component: "request_logger" },
      },
      remediationLifecycle: {
        workflow_chain_status: "current",
        lifecycle_phase: "REMEDIATING",
        implementation: {
          implementation_id: "IMP-1",
          remediation_action_id: "ACT-1",
          implementation_summary: "Applied reviewed redaction.",
          implementation_mode: "controlled_patch",
          status: "rolled_back",
          patch_proposal_id: "PATCH-1",
        },
        test_execution: { execution_id: "TEST-1", status: "failed", workflow_status: "current" },
        controlled_retest: null,
        verification_result: null,
        learning_eligible: false,
        rollback_status: "succeeded",
        rollback_verified: true,
        rollback_verification: "passed",
      },
    } as unknown as IncidentWorkspaceData;

    render(<ControlledRemediationLifecyclePanel data={data} canOperate={false} onRefresh={vi.fn()} />);
    expect(screen.getByTestId("rollback-banner")).toHaveTextContent(/Implementation Failed/i);
    expect(screen.getByTestId("rollback-banner")).toHaveTextContent(/Rollback: Verified/i);
    expect(screen.getByTestId("lifecycle-phase")).toHaveTextContent("REMEDIATING");
    expect(screen.queryByText(/Verification passed based on available controlled retest evidence/i)).not.toBeInTheDocument();
  });
});
