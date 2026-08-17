import { sanitizeString } from "../utils/safety";
import type { WizardStepStatus } from "./WorkflowStepCard";

/**
 * Compact progress strip for the Investigation Wizard. Each segment
 * represents one workflow step; the visual state mirrors the step's
 * runtime status (not_started / ready / running / complete / failed /
 * blocked).
 *
 * Status text is sanitized before display so a backend-supplied value
 * can never leak a sensitive literal into the header strip.
 */
export interface WizardProgressItem {
  id: string;
  label: string;
  status: WizardStepStatus;
}

const STATUS_CLASS: Record<WizardStepStatus, string> = {
  not_started: "bg-slate-200 text-slate-700",
  ready: "bg-blue-100 text-navy-700",
  running: "bg-amber-100 text-amber-800",
  complete: "bg-emerald-100 text-emerald-800",
  failed: "bg-red-100 text-red-800",
  blocked: "bg-orange-100 text-orange-800",
};

export default function WorkflowProgressBar({
  steps,
  activeStepId,
}: {
  steps: WizardProgressItem[];
  activeStepId?: string | null;
}) {
  return (
    <ol
      data-testid="wizard-progress"
      className="flex flex-wrap gap-2 text-xs"
    >
      {steps.map((step, index) => {
        const cls = STATUS_CLASS[step.status] ?? STATUS_CLASS.not_started;
        const isActive = step.id === activeStepId;
        return (
          <li
            key={step.id}
            className={`flex items-center gap-1 rounded-full px-2.5 py-1 font-medium ${cls} ${
              isActive ? "ring-2 ring-slate-900" : ""
            }`}
          >
            <span className="font-mono text-xs text-slate-700">
              {String(index + 1).padStart(2, "0")}
            </span>
            <span>{sanitizeString(step.label)}</span>
          </li>
        );
      })}
    </ol>
  );
}
