import { AlertTriangle, CheckCircle2, Circle, Clock3, LockKeyhole } from "lucide-react";
import { sanitizeString } from "../utils/safety";
import { userFacingLabel } from "../utils/userFacing";

const palette: Record<string, string> = {
  critical: "bg-red-50 text-red-800 ring-1 ring-inset ring-red-600/15",
  high: "bg-orange-50 text-orange-800 ring-1 ring-inset ring-orange-600/15",
  medium: "bg-amber-50 text-amber-800 ring-1 ring-inset ring-amber-600/15",
  low: "bg-teal-50 text-teal-800 ring-1 ring-inset ring-teal-600/15",
  new: "bg-red-50 text-red-700 ring-1 ring-inset ring-red-500/15",
  open: "bg-red-50 text-red-700 ring-1 ring-inset ring-red-500/15",
  investigating: "bg-navy-50 text-navy-800 ring-1 ring-inset ring-navy-600/15",
  under_review: "bg-amber-50 text-amber-800 ring-1 ring-inset ring-amber-600/15",
  linked_to_incident: "bg-accent-soft text-teal-800 ring-1 ring-inset ring-teal-600/15",
  linked: "bg-accent-soft text-teal-800 ring-1 ring-inset ring-teal-600/15",
  dismissed_false_positive: "bg-slate-100 text-slate-600 ring-1 ring-inset ring-slate-500/15",
  dismissed: "bg-slate-100 text-slate-600 ring-1 ring-inset ring-slate-500/15",
  resolved: "bg-teal-50 text-teal-800 ring-1 ring-inset ring-teal-600/15",
  closed: "bg-teal-50 text-teal-800 ring-1 ring-inset ring-teal-600/15",
  healthy: "bg-teal-50 text-teal-800 ring-1 ring-inset ring-teal-600/15",
  unhealthy: "bg-red-50 text-red-800 ring-1 ring-inset ring-red-600/15",
  monitoring: "bg-teal-50 text-teal-800 ring-1 ring-inset ring-teal-600/15",
  pending: "bg-slate-100 text-slate-600 ring-1 ring-inset ring-slate-500/15",
  complete: "bg-teal-50 text-teal-800 ring-1 ring-inset ring-teal-600/15",
  ready: "bg-sky-50 text-sky-800 ring-1 ring-inset ring-sky-600/15",
  blocked: "bg-amber-50 text-amber-800 ring-1 ring-inset ring-amber-600/15",
  failed: "bg-red-50 text-red-800 ring-1 ring-inset ring-red-600/15",
  passed: "bg-teal-50 text-teal-800 ring-1 ring-inset ring-teal-600/15",
  active: "bg-teal-50 text-teal-800 ring-1 ring-inset ring-teal-600/15",
  inactive: "bg-slate-100 text-slate-600 ring-1 ring-inset ring-slate-500/15",
};

function normalizeKey(value: string): string {
  return value.toLowerCase().replace(/[\s-]+/g, "_");
}

export function badgeClassFor(value: string): string {
  const key = normalizeKey(value);
  return palette[key] ?? "bg-slate-100 text-slate-600 ring-1 ring-inset ring-slate-500/15";
}

function Icon({ value }: { value: string }) {
  const key = normalizeKey(value);
  const cls = "h-3 w-3 shrink-0";
  if (["critical", "high", "new", "open", "unhealthy", "failed"].includes(key)) {
    return <AlertTriangle className={cls} aria-hidden="true" />;
  }
  if (["resolved", "closed", "healthy", "complete", "passed", "active", "monitoring"].includes(key)) {
    return <CheckCircle2 className={cls} aria-hidden="true" />;
  }
  if (["blocked", "pending", "pending_verification", "pending_unassigned"].includes(key)) {
    return key === "blocked" ? <LockKeyhole className={cls} aria-hidden="true" /> : <Clock3 className={cls} aria-hidden="true" />;
  }
  return <Circle className={cls} aria-hidden="true" />;
}

/** Unified severity/status chip — icon + label + color. Technical value in title. */
export default function StatusBadge({
  value,
  className = "",
}: {
  value: string;
  className?: string;
}) {
  const raw = sanitizeString(value);
  const label = userFacingLabel(raw);
  return (
    <span
      title={raw}
      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-medium capitalize ${badgeClassFor(value)} ${className}`}
    >
      <Icon value={value} />
      {label}
    </span>
  );
}
