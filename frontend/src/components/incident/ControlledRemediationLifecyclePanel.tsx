import { useState } from "react";
import { remediationLifecycleApi, type RemediationTestResult } from "../../api/remediationLifecycleClient";
import type { IncidentWorkspaceData } from "../../pages/incidents/types";
import { sanitizeString } from "../../utils/safety";
import StatusBadge from "../StatusBadge";
import { getMissingRetestDimensions, isExactRetestReady } from "../../utils/controlledRemediation";

export default function ControlledRemediationLifecyclePanel({
  data,
  canOperate,
  onRefresh,
}: {
  data: IncidentWorkspaceData;
  canOperate: boolean;
  onRefresh: () => void;
}) {
  const incidentId = data.incident.incident_id;
  const action = data.remediationActions.find(
    (item) => item.remediation_action_id === data.workflow.remediation_action_id,
  );
  const implementation = data.remediationLifecycle?.implementation;
  const retest = data.remediationLifecycle?.controlled_retest;
  const [summary, setSummary] = useState("");
  const [reference, setReference] = useState("");
  const [sessionTest, setSessionTest] = useState<RemediationTestResult | null>(null);
  const [findingId, setFindingId] = useState("");
  const [syntheticOutput, setSyntheticOutput] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const test = sessionTest ?? data.remediationLifecycle?.test_execution;
  const expectedDimensions = {
    service_name: data.currentDiagnosis?.affected_service,
    endpoint: data.currentDiagnosis?.affected_endpoint,
    exposure_location: data.currentDiagnosis?.primary_remediation.exposure_location,
    component: data.currentDiagnosis?.primary_remediation.affected_component,
  };
  const missingDimensions = getMissingRetestDimensions(expectedDimensions);

  async function act(name: string, task: () => Promise<unknown>) {
    setBusy(name);
    setError(null);
    setMessage(null);
    try {
      await task();
      setMessage(`${name} recorded. Workflow status refreshed.`);
      onRefresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : `${name} could not be recorded.`);
    } finally {
      setBusy(null);
    }
  }

  const blockedStatuses = new Set(["stale", "blocked", "invalid"]);
  const blocked = blockedStatuses.has(data.workflow.workflow_chain_status ?? "blocked")
    || blockedStatuses.has(data.remediationLifecycle?.workflow_chain_status ?? "blocked");
  const exactRetestReady = isExactRetestReady(blocked, retest, test);
  const lifecyclePhase = data.remediationLifecycle?.lifecycle_phase
    ?? (data.workflow as { lifecycle_phase?: string }).lifecycle_phase
    ?? "OPEN";
  const rolledBack = Boolean(
    data.remediationLifecycle?.rollback_verified
    || data.remediationLifecycle?.rollback_status === "succeeded"
    || implementation?.status === "rolled_back"
    || test?.status === "failed",
  );
  const showSuccessGreen = data.remediationLifecycle?.verification_result === "passed"
    && data.remediationLifecycle?.learning_eligible
    && !rolledBack;
  return (
    <div className="space-y-4" data-testid="controlled-remediation-lifecycle">
      <p className="text-sm text-ink-muted">
        Record a human-owned implementation, run one allowlisted test, create an explicit controlled retest, then verify the exact current chain.
        A passed allowlisted test does not mean the fix is verified.
      </p>
      <p className="text-xs text-ink-subtle" data-testid="lifecycle-phase">
        Lifecycle phase: {lifecyclePhase}
      </p>
      {rolledBack ? (
        <div
          className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-950"
          role="status"
          data-testid="rollback-banner"
        >
          <p className="font-medium">Implementation Failed</p>
          <p>
            Rollback:{" "}
            {data.remediationLifecycle?.rollback_verified ? "Verified" : (data.remediationLifecycle?.rollback_verification ?? "recorded")}
          </p>
          <p>Incident remains unresolved. Next action: Review remediation.</p>
          <p className="mt-1 text-xs">
            Do not treat this as successful completion. No verified learning is created from a rolled-back attempt.
          </p>
        </div>
      ) : null}
      {showSuccessGreen ? (
        <p className="rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-900" role="status">
          Verification passed based on available controlled retest evidence. Learning eligibility is backend-gated.
        </p>
      ) : null}
      {blocked ? (
        <p className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900" role="status">
          {data.workflow.blocked_reasons?.join(" ") || "The current provenance chain is blocked or stale."}
        </p>
      ) : null}

      <ol className="space-y-4">
        <li className="rounded-md border border-slate-200 p-4">
          <StepTitle number="1" title="Implementation record" status={implementation?.status} />
          {implementation ? (
            <p className="mt-2 break-words text-sm text-ink-muted">
              {sanitizeString(implementation.implementation_summary)} · {implementation.implementation_mode.replaceAll("_", " ")}
            </p>
          ) : canOperate && action ? (
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <Field label="Safe implementation summary" value={summary} onChange={setSummary} />
              <Field label="Safe change reference (optional)" value={reference} onChange={setReference} />
              <button
                className="btn-primary sm:col-span-2 sm:w-fit"
                disabled={Boolean(busy) || blocked || !summary.trim()}
                onClick={() => void act("Implementation", () => remediationLifecycleApi.recordImplementation(incidentId, {
                  remediation_action_id: action.remediation_action_id,
                  implementation_mode: "manual",
                  implementation_summary: summary,
                  change_reference_safe: reference || null,
                }))}
              >{busy === "Implementation" ? "Recording…" : "Record manual implementation"}</button>
            </div>
          ) : <p className="mt-2 text-sm text-ink-muted">A current human-approved diagnosis action is required.</p>}
        </li>

        <li className="rounded-md border border-slate-200 p-4">
          <StepTitle number="2" title="Allowlisted test" status={test?.status} />
          <p className="mt-2 text-xs text-ink-subtle">Runs the fixed privacy regression profile. Commands cannot be supplied by users or AI.</p>
          {canOperate && implementation && action ? (
            <button
              className="btn-secondary mt-3"
              disabled={Boolean(busy) || implementation.status !== "completed"}
              onClick={() => void act("Allowlisted test", async () => {
                const result = await remediationLifecycleApi.runTest(incidentId, {
                  profile: "privacy_regression",
                  remediation_action_id: action.remediation_action_id,
                  implementation_id: implementation.implementation_id,
                  patch_proposal_id: implementation.patch_proposal_id,
                });
                setSessionTest(result);
              })}
            >{busy === "Allowlisted test" ? "Running…" : "Run allowlisted privacy regression"}</button>
          ) : null}
          {test ? <p className="mt-2 text-sm" role="status">Test execution {test.execution_id}: {test.status}. Output is masked.</p> : null}
        </li>

        <li className="rounded-md border border-slate-200 p-4">
          <StepTitle number="3" title="Controlled retest" status={retest?.status} />
          {retest ? (
            <p className="mt-2 text-sm text-ink-muted">
              Dimensions match: {retest.dimensions_match ? "Yes" : "No"}. Raw exposure after change: {retest.raw_exposure_after_change == null ? "Inconclusive" : retest.raw_exposure_after_change ? "Detected" : "Not detected"}.
            </p>
          ) : canOperate && implementation && test?.status === "passed" ? (
            <div className="mt-3 space-y-3">
              <Field label="Original detection ID" value={findingId} onChange={setFindingId} />
              <label className="block text-sm font-medium text-ink-muted">Synthetic retest output only
                <textarea className="field-control mt-1 block w-full" rows={3} value={syntheticOutput} onChange={(event) => setSyntheticOutput(event.target.value)} maxLength={100000} aria-describedby="synthetic-retest-help" />
              </label>
              <p id="synthetic-retest-help" className="text-xs text-ink-subtle">Do not paste customer data, credentials, AML details, or production logs.</p>
              {missingDimensions.length ? <p className="text-sm text-amber-900" role="status">Controlled retest is blocked: the server-backed diagnosis is missing {missingDimensions.join(", ")}.</p> : null}
              <button className="btn-secondary" disabled={Boolean(busy) || Boolean(missingDimensions.length) || !findingId.trim() || !syntheticOutput.trim()} onClick={() => void act("Controlled retest", () => remediationLifecycleApi.recordControlledRetest(incidentId, {
                implementation_id: implementation.implementation_id,
                test_execution_id: test.execution_id,
                original_finding_id: findingId,
                synthetic_output: syntheticOutput,
                ...expectedDimensions,
                source_type: "synthetic_retest",
              }))}>{busy === "Controlled retest" ? "Recording…" : "Record controlled retest"}</button>
            </div>
          ) : <p className="mt-2 text-sm text-ink-muted">A persisted passed allowlisted test for this current implementation is required.</p>}
        </li>

        <li className="rounded-md border border-slate-200 p-4">
          <StepTitle number="4" title="Exact-chain verification" status={data.remediationLifecycle?.verification_result} />
          {canOperate && retest ? <button className="btn-primary mt-3" disabled={Boolean(busy) || !exactRetestReady} onClick={() => void act("Fix verification", () => remediationLifecycleApi.verify(incidentId, retest.controlled_retest_id))}>{busy === "Fix verification" ? "Verifying…" : "Verify current controlled retest"}</button> : null}
          <p className="mt-2 text-xs text-ink-subtle">Learning eligibility: {data.remediationLifecycle?.learning_eligible ? "Eligible" : "Not eligible"}. The backend decides this only after a complete current passed chain.</p>
        </li>
      </ol>
      {error ? <p className="text-sm text-red-700" role="alert">{sanitizeString(error)}</p> : null}
      {message ? <p className="text-sm text-emerald-700" role="status">{message}</p> : null}
    </div>
  );
}

function StepTitle({ number, title, status }: { number: string; title: string; status?: string | null }) {
  return <div className="flex flex-wrap items-center gap-2"><h3 className="font-semibold text-navy-900">{number}. {title}</h3>{status ? <StatusBadge value={status} /> : <span className="text-xs text-ink-subtle">Not recorded</span>}</div>;
}

function Field({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return <label className="block text-sm font-medium text-ink-muted">{label}<input className="field-control mt-1 block w-full" value={value} onChange={(event) => onChange(event.target.value)} maxLength={2000} /></label>;
}
