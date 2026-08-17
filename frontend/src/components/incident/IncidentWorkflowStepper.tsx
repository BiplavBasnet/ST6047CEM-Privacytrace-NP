import { CheckCircle2, Circle, LockKeyhole } from "lucide-react";
import { Link } from "react-router-dom";
import type { IncidentWorkflowState, WorkflowStage } from "../../api/client";
import { userFacingLabel } from "../../utils/userFacing";

const ROUTES: Record<string, string> = {
  overview: "overview",
  root_cause: "root-cause",
  human_review: "review",
  remediation: "remediation",
  fix_verification: "verification",
  final_report: "report",
};

const STAGE_LABELS: Record<string, string> = {
  overview: "Overview",
  root_cause: "Likely Cause",
  human_review: "Review",
  remediation: "Remediation",
  fix_verification: "Verify Fix",
  final_report: "Report",
};

const TONES: Record<WorkflowStage["status"], string> = {
  complete: "text-teal-800",
  ready: "text-navy-900",
  pending: "text-slate-500",
  blocked: "text-amber-800",
};

export default function IncidentWorkflowStepper({
  workflow,
  activeStage,
}: {
  workflow: IncidentWorkflowState;
  activeStage: string;
}) {
  return (
    <nav aria-label="Incident workflow" data-testid="incident-workspace-steps">
      <ol className="flex gap-0 overflow-x-auto border-b border-slate-200">
        {workflow.stages.map((stage, index) => {
          const route = ROUTES[stage.code];
          const active = route === activeStage;
          const Icon = stage.completed ? CheckCircle2 : stage.available ? Circle : LockKeyhole;
          const label = STAGE_LABELS[stage.code] ?? stage.label;
          return (
            <li key={stage.code} className="min-w-0 flex-1">
              <Link
                to={`/incidents/${encodeURIComponent(workflow.incident_id)}/${route}`}
                aria-current={active ? "step" : undefined}
                title={stage.blocked_reason ?? `${label} — ${userFacingLabel(stage.status)}`}
                className={`flex min-h-9 items-center justify-center gap-1.5 border-b-2 px-2 py-1.5 text-xs ${TONES[stage.status]} ${
                  active ? "border-navy-800 font-semibold" : "border-transparent hover:border-slate-300"
                }`}
              >
                <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span className="min-w-0 truncate">
                  {index + 1}. {label}
                </span>
                {stage.blocked_reason ? <span className="sr-only">{stage.blocked_reason}</span> : null}
              </Link>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
