import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { sanitizeString } from "../utils/safety";
import SafeErrorMessage from "./SafeErrorMessage";

export type WizardStepStatus =
  | "not_started"
  | "ready"
  | "running"
  | "complete"
  | "failed"
  | "blocked";

export interface WizardStepLink {
  label: string;
  to: string;
}

const STATUS_BADGE: Record<
  WizardStepStatus,
  { label: string; className: string }
> = {
  not_started: {
    label: "Not started",
    className: "bg-slate-100 text-slate-700",
  },
  ready: {
    label: "Ready",
    className: "bg-blue-100 text-navy-700",
  },
  running: {
    label: "Running",
    className: "bg-amber-100 text-amber-800",
  },
  complete: {
    label: "Complete",
    className: "bg-emerald-100 text-emerald-800",
  },
  failed: {
    label: "Failed",
    className: "bg-red-100 text-red-800",
  },
  blocked: {
    label: "Blocked",
    className: "bg-orange-100 text-orange-800",
  },
};

/**
 * One card in the guided Investigation Wizard. Each card explains:
 * - what the step does
 * - why it matters
 * - which permission is required
 * - the next action button
 * - safe error message (if the step failed)
 * - related links (incident / evidence / report)
 *
 * Raw API responses are never rendered. The parent passes only safe,
 * already-sanitized strings, but every text field is run through
 * `sanitizeString` again here as defence-in-depth.
 */
export default function WorkflowStepCard({
  stepNumber,
  title,
  description,
  why,
  requiredPermission,
  hasPermission,
  status,
  errorMessage,
  resultSummary,
  actionLabel,
  onAction,
  actionDisabled,
  links,
  children,
}: {
  stepNumber: number;
  title: string;
  description: string;
  why: string;
  requiredPermission?: string | null;
  hasPermission: boolean;
  status: WizardStepStatus;
  errorMessage?: string | null;
  resultSummary?: string | null;
  actionLabel: string;
  onAction?: () => void;
  actionDisabled?: boolean;
  links?: WizardStepLink[];
  children?: ReactNode;
}) {
  const badge = STATUS_BADGE[status] ?? STATUS_BADGE.not_started;
  const buttonDisabled =
    actionDisabled ||
    !onAction ||
    !hasPermission ||
    status === "running" ||
    status === "complete";

  return (
    <article
      data-testid={`wizard-step-${stepNumber}`}
      data-status={status}
      className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm"
    >
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-3">
          <span className="rounded-full bg-navy-700 px-2.5 py-0.5 font-mono text-xs font-medium text-white">
            {String(stepNumber).padStart(2, "0")}
          </span>
          <h3 className="text-sm font-semibold text-slate-900">
            {sanitizeString(title)}
          </h3>
        </div>
        <span
          data-testid={`wizard-step-${stepNumber}-status`}
          className={`inline-flex rounded-full px-2.5 py-0.5 text-xs font-medium ${badge.className}`}
        >
          {badge.label}
        </span>
      </header>

      <p className="mt-3 text-sm text-slate-700">{sanitizeString(description)}</p>
      <details className="mt-2">
        <summary className="cursor-pointer text-xs font-medium text-ink-muted">Why this step</summary>
        <p className="mt-1 text-xs text-slate-500">{sanitizeString(why)}</p>
        {requiredPermission ? (
          <p className="mt-1 text-xs text-slate-500">
            Permission:{" "}
            <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-xs">
              {sanitizeString(requiredPermission)}
            </code>
          </p>
        ) : null}
      </details>

      {!hasPermission && requiredPermission ? (
        <p className="mt-2 rounded-md border border-orange-200 bg-orange-50 p-2 text-xs text-orange-900">
          Your current role does not have <code>{sanitizeString(requiredPermission)}</code>.
          Ask an administrator to grant this permission to continue.
        </p>
      ) : null}

      {children ? <div className="mt-3 text-sm text-slate-700">{children}</div> : null}

      {resultSummary ? (
        <p className="mt-3 rounded-md border border-emerald-200 bg-emerald-50 p-2 text-xs text-emerald-900">
          {sanitizeString(resultSummary)}
        </p>
      ) : null}

      {status === "failed" && errorMessage ? (
        <div className="mt-3">
          <SafeErrorMessage
            title="Step failed"
            message={errorMessage}
            hint="Workflow stopped. Resolve this step before continuing."
          />
        </div>
      ) : null}

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={onAction}
          disabled={buttonDisabled}
          className="rounded-lg bg-navy-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-navy-800 disabled:cursor-not-allowed disabled:bg-slate-300 disabled:text-slate-500"
        >
          {sanitizeString(actionLabel)}
        </button>
        {links?.map((link) => (
          <Link
            key={`${link.label}-${link.to}`}
            to={link.to}
            className="text-xs font-medium text-accent underline hover:text-blue-900"
          >
            {sanitizeString(link.label)}
          </Link>
        ))}
      </div>
    </article>
  );
}
