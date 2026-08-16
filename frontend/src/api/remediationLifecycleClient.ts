import { request } from "./client";

export interface RemediationImplementation {
  implementation_id: string;
  incident_id: string;
  remediation_action_id: string;
  patch_proposal_id: string | null;
  implementation_mode: "manual" | "external_configuration_change" | "controlled_patch";
  change_reference_safe: string | null;
  change_hash: string | null;
  implementation_summary: string;
  status: string;
  implemented_at: string;
  workflow_status: string;
}

export interface ControlledRetest {
  controlled_retest_id: string;
  incident_id: string;
  implementation_id: string;
  test_execution_id: string;
  original_finding_id: string;
  retest_finding_id: string | null;
  service_name: string | null;
  endpoint: string | null;
  exposure_location: string | null;
  sensitive_type: string | null;
  component: string | null;
  environment: string | null;
  dimensions_match: boolean;
  raw_exposure_after_change: boolean | null;
  finding_count: number;
  safety_status: string;
  status: string;
  completed_at: string;
  workflow_status: string;
}

export interface RemediationLifecycle {
  incident_id: string;
  implementation: RemediationImplementation | null;
  test_execution: RemediationTestExecution | null;
  controlled_retest: ControlledRetest | null;
  fix_verification_id: number | null;
  verification_outcome_id: string | null;
  verification_result: string | null;
  verified_case_id: string | null;
  learning_eligible: boolean;
  workflow_chain_status: string;
  lifecycle_phase?: string;
  rollback_execution_id?: string | null;
  rollback_status?: string | null;
  rollback_verification?: string | null;
  rollback_verified?: boolean | null;
}

export interface RemediationTestExecution {
  execution_id: string;
  implementation_id: string | null;
  remediation_action_id: string | null;
  test_profile: string;
  status: string;
  safety_status: string | null;
  raw_leakage_count: number | null;
  safe_output_summary: string | null;
  workflow_status: string;
}

export interface RemediationTestResult {
  execution_id: string;
  profile: string;
  status: string;
  passed: boolean;
  safe_output_summary: string;
  raw_value_leakage_result: number;
  workflow_status?: string;
  rollback_execution_id?: string;
  rollback_status?: string;
  rollback_verification?: string | null;
}

export interface VerifyFixResult {
  verification_id: number;
  verification_status: string;
  safe_summary: string;
  verification_outcome_id: string | null;
  eligible_for_learning: boolean;
}

const incidentPath = (incidentId: string) => `/incidents/${encodeURIComponent(incidentId)}`;

export const remediationLifecycleApi = {
  get: (incidentId: string) =>
    request<RemediationLifecycle>(`${incidentPath(incidentId)}/remediation-lifecycle`),

  recordImplementation: (
    incidentId: string,
    payload: {
      remediation_action_id: string;
      implementation_mode: "manual" | "external_configuration_change";
      implementation_summary: string;
      change_reference_safe?: string | null;
    },
  ) =>
    request<RemediationImplementation>(`${incidentPath(incidentId)}/implementations`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  runTest: (
    incidentId: string,
    payload: {
      profile: string;
      remediation_action_id: string;
      implementation_id: string;
      patch_proposal_id?: string | null;
    },
  ) =>
    request<RemediationTestResult>(`${incidentPath(incidentId)}/remediation-tests/run`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  recordControlledRetest: (
    incidentId: string,
    payload: {
      implementation_id: string;
      test_execution_id: string;
      original_finding_id: string;
      source_type: string;
      synthetic_output: string;
      service_name?: string | null;
      endpoint?: string | null;
      exposure_location?: string | null;
      component?: string | null;
      environment?: string | null;
    },
  ) =>
    request<ControlledRetest>(`${incidentPath(incidentId)}/controlled-retests`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  verify: (incidentId: string, controlledRetestId: string) =>
    request<VerifyFixResult>(`${incidentPath(incidentId)}/verify-fix`, {
      method: "POST",
      body: JSON.stringify({ controlled_retest_id: controlledRetestId }),
    }),
};
