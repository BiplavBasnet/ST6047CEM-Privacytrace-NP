import { ArrowRight, LockKeyhole } from "lucide-react";
import { Link } from "react-router-dom";
import type { WorkflowNextAction as WorkflowNextActionType } from "../../api/client";
import { sanitizeString } from "../../utils/safety";

export default function WorkflowNextAction({ action }: { action: WorkflowNextActionType }) {
  return (
    <section className="space-y-2" data-testid="workflow-next-action">
      <div>
        <p className="eyebrow">Next action</p>
        <h2 className="mt-1 text-sm font-semibold tracking-tight text-navy-900">{sanitizeString(action.label)}</h2>
        <p className="mt-1 text-xs text-ink-muted">{sanitizeString(action.description)}</p>
        {action.blocked_reason ? <p className="mt-1 text-xs text-amber-800">{sanitizeString(action.blocked_reason)}</p> : null}
      </div>
      {action.blocked ? (
        <span className="inline-flex items-center gap-2 text-sm font-medium text-amber-800">
          <LockKeyhole className="h-4 w-4" aria-hidden="true" /> Blocked
        </span>
      ) : (
        <Link to={action.target} className="btn-primary w-full">
          {sanitizeString(action.label)} <ArrowRight className="h-4 w-4" aria-hidden="true" />
        </Link>
      )}
    </section>
  );
}
