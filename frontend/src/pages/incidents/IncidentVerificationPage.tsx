import Card from "../../components/Card";
import ControlledRemediationLifecyclePanel from "../../components/incident/ControlledRemediationLifecyclePanel";
import type { IncidentWorkspaceData } from "./types";
import type { RemediationLifecycle } from "../../api/remediationLifecycleClient";

const SEQUENCE = ["Implementation", "Test", "Retest", "Verification", "Outcome"] as const;

function stepTone(step: (typeof SEQUENCE)[number], lifecycle: RemediationLifecycle | null, rolledBack: boolean): string {
  const pending = "border-slate-200 bg-slate-50 text-navy-900";
  const pass = "border-teal-300 bg-teal-50 text-teal-900";
  const fail = "border-red-300 bg-red-50 text-red-900";
  const warn = "border-amber-300 bg-amber-50 text-amber-950";
  if (!lifecycle) return pending;
  if (step === "Implementation") {
    const status = lifecycle.implementation?.status;
    if (status === "rolled_back") return fail;
    if (status && status !== "pending") return pass;
  }
  if (step === "Test") {
    const status = lifecycle.test_execution?.status;
    if (status === "failed") return fail;
    if (status === "passed") return pass;
  }
  if (step === "Retest") {
    const status = lifecycle.controlled_retest?.status;
    if (status === "failed") return fail;
    if (status === "passed") return pass;
  }
  if (step === "Verification") {
    const result = lifecycle.verification_result;
    if (result === "failed") return fail;
    if (result === "passed") return pass;
    if (result === "inconclusive") return warn;
  }
  if (step === "Outcome") {
    if (rolledBack) return fail;
    if (lifecycle.verification_result === "passed") return pass;
    if (lifecycle.verification_result === "failed") return fail;
    if (lifecycle.verification_result === "inconclusive") return warn;
  }
  return pending;
}

export default function IncidentVerificationPage({
  data,
  onRefresh,
  canVerify,
}: {
  data: IncidentWorkspaceData;
  onRefresh: () => void;
  canVerify: boolean;
  canRetest: boolean;
}) {
  const phase = data.remediationLifecycle?.lifecycle_phase ?? "OPEN";
  const rolledBack = Boolean(
    data.remediationLifecycle?.rollback_verified
    || data.remediationLifecycle?.rollback_status === "succeeded"
    || data.remediationLifecycle?.implementation?.status === "rolled_back",
  );
  return (
    <Card title="Verify the fix">
      <p className="text-sm text-ink-muted">
        A passed allowlisted test does not mean the fix is verified. Verification uses the controlled retest chain.
      </p>
      <ol className="mt-3 flex flex-wrap gap-1 text-xs font-medium" aria-label="Verification sequence">
        {SEQUENCE.map((step, index) => {
          const tone = stepTone(step, data.remediationLifecycle, rolledBack);
          return (
          <li key={step} className="flex items-center gap-1">
            <span className={`rounded-md border px-2 py-1 ${tone}`}>{step}</span>
            {index < SEQUENCE.length - 1 ? <span className="text-ink-subtle" aria-hidden="true">→</span> : null}
          </li>
          );
        })}
      </ol>
      <p className="mt-2 text-xs text-ink-subtle">Current phase: {phase}</p>
      {rolledBack ? (
        <p className="mt-3 rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-950" role="status">
          Fix attempt failed. Rollback is recorded. The incident remains unresolved.
        </p>
      ) : null}
      <div className="mt-4">
        <ControlledRemediationLifecyclePanel
          data={data}
          canOperate={canVerify}
          onRefresh={onRefresh}
        />
      </div>
      {!canVerify ? (
        <p className="mt-4 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
          Your role can view this lifecycle but cannot record implementation, retest, or verification events.
        </p>
      ) : null}
      <p className="mt-4 text-xs text-ink-subtle">
        Controlled patching is a demo-fixture sandbox capability only. It does not change production code.
      </p>
    </Card>
  );
}
