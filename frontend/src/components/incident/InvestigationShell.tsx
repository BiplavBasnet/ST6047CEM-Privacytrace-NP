import type { ReactNode } from "react";
import type { IncidentDetail, IncidentWorkflowState, RootCauseEvidenceStrength } from "../../api/client";
import IncidentSummaryHeader from "./IncidentSummaryHeader";
import IncidentWorkflowStepper from "./IncidentWorkflowStepper";
import WorkflowNextAction from "./WorkflowNextAction";

function targetStage(target: string): string | null {
  const match = target.match(/\/incidents\/[^/]+\/([^/?#]+)/);
  return match?.[1] ?? null;
}

export default function InvestigationShell({
  incident,
  source,
  workflow,
  rootStrength,
  activeStage,
  children,
}: {
  incident: IncidentDetail;
  source: string;
  workflow: IncidentWorkflowState;
  rootStrength: RootCauseEvidenceStrength | null;
  activeStage: string;
  children: ReactNode;
}) {
  const next = workflow.next_action;
  const nextStage = next?.target ? targetStage(next.target) : null;
  const nextIsCurrentStage = Boolean(nextStage && nextStage === activeStage && !next.blocked);
  const current = workflow.stages.find((stage) => {
    const route = stage.code.replaceAll("_", "-");
    return route === activeStage || (stage.code === "root_cause" && activeStage === "root-cause")
      || (stage.code === "human_review" && activeStage === "review")
      || (stage.code === "fix_verification" && activeStage === "verification")
      || (stage.code === "final_report" && activeStage === "report");
  });

  return (
    <div className="space-y-3">
      <IncidentSummaryHeader
        incident={incident}
        source={source}
        rootStrength={rootStrength}
        workflow={workflow}
        remediationActions={[]}
      />
      <IncidentWorkflowStepper workflow={workflow} activeStage={activeStage} />
      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(240px,18rem)]">
        <div className="min-w-0">{children}</div>
        <aside className="space-y-3 border border-slate-200 bg-white p-3 xl:sticky xl:top-16" aria-label="Investigation context">
          <div>
            <p className="eyebrow">Current stage</p>
            <p className="mt-1 text-sm font-semibold text-navy-900">{current?.label ?? activeStage}</p>
          </div>
          {nextIsCurrentStage ? (
            <p className="text-sm text-ink-muted">Continue in the main panel.</p>
          ) : next ? (
            <WorkflowNextAction action={next} />
          ) : (
            <p className="text-sm text-ink-muted">No next action is available.</p>
          )}
          {rootStrength ? (
            <dl className="grid grid-cols-3 gap-2 border-t border-slate-100 pt-3 text-center">
              <div>
                <dt className="text-[11px] text-ink-subtle">Supports</dt>
                <dd className="text-sm font-semibold text-navy-900">{rootStrength.supporting_evidence.length}</dd>
              </div>
              <div>
                <dt className="text-[11px] text-ink-subtle">Against</dt>
                <dd className="text-sm font-semibold text-navy-900">{rootStrength.contradicting_evidence.length}</dd>
              </div>
              <div>
                <dt className="text-[11px] text-ink-subtle">Missing</dt>
                <dd className="text-sm font-semibold text-navy-900">{rootStrength.missing_evidence.length}</dd>
              </div>
            </dl>
          ) : null}
        </aside>
      </div>
    </div>
  );
}
