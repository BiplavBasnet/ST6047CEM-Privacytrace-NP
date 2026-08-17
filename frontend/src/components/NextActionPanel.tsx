import { sanitizeString } from "../utils/safety";

/**
 * Compact "Next Recommended Action" panel used both on the dashboard /
 * incident detail page and in the Investigation Wizard header. The
 * `actionLabel`, `description` and `targetStep` strings are sanitized
 * before display.
 */
export default function NextActionPanel({
  actionLabel,
  description,
  targetStep,
  disabled,
  onAction,
  empty,
}: {
  actionLabel: string;
  description: string;
  targetStep?: string | null;
  disabled?: boolean;
  onAction?: () => void;
  empty?: boolean;
}) {
  if (empty) {
    return (
      <div
        data-testid="next-action-panel-empty"
        className="rounded-md border border-slate-200 bg-slate-50 p-3 text-sm text-slate-600"
      >
        No further action recommended. Review the incident summary and the
        generated report.
      </div>
    );
  }
  return (
    <div
      data-testid="next-action-panel"
      className="rounded-md border border-blue-200 bg-blue-50 p-3"
    >
      <p className="text-xs font-medium uppercase tracking-wide text-accent">
        Next recommended action
      </p>
      <p className="mt-1 text-sm font-semibold text-slate-900">
        {sanitizeString(actionLabel)}
      </p>
      <p className="mt-1 text-xs text-slate-700">{sanitizeString(description)}</p>
      {targetStep ? (
        <p className="mt-1 text-xs text-slate-500">
          Wizard step: {sanitizeString(targetStep)}
        </p>
      ) : null}
      {onAction ? (
        <button
          type="button"
          onClick={onAction}
          disabled={disabled}
          className="mt-3 rounded-lg bg-navy-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-navy-800 disabled:cursor-not-allowed disabled:bg-slate-300 disabled:text-slate-500"
        >
          Take this action
        </button>
      ) : null}
    </div>
  );
}
