import type { ReactNode } from "react";
import { sanitizeString } from "../../utils/safety";

export function relativeTime(value: string | null | undefined): string {
  if (!value) return "—";
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return sanitizeString(value);
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 45) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
  return new Date(then).toLocaleDateString();
}

export default function RelativeTime({
  value,
  className = "",
  title,
}: {
  value: string | null | undefined;
  className?: string;
  title?: string;
}) {
  const label = relativeTime(value);
  const full = value && !Number.isNaN(new Date(value).getTime()) ? new Date(value).toLocaleString() : undefined;
  return (
    <time className={className} dateTime={value ?? undefined} title={title ?? full}>
      {label}
    </time>
  );
}

export function FilterBar({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`flex flex-wrap items-end gap-3 ${className}`}>{children}</div>
  );
}

export function FilterField({
  label,
  value,
  onChange,
  children,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  children: ReactNode;
}) {
  return (
    <label className="block min-w-[11rem]">
      <span className="mb-1.5 block text-xs font-medium text-ink-muted">{label}</span>
      <select
        aria-label={label}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="field-control w-full"
      >
        {children}
      </select>
    </label>
  );
}

export function QueueToolbar({
  countLabel,
  children,
}: {
  countLabel?: string;
  children?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-3">
      {countLabel ? <p className="text-xs font-semibold text-ink-subtle">{countLabel}</p> : <span />}
      {children ? <div className="flex flex-wrap items-center gap-2">{children}</div> : null}
    </div>
  );
}

export function SegmentedTabs({
  tabs,
  value,
  onChange,
  labelledBy,
}: {
  tabs: { id: string; label: string }[];
  value: string;
  onChange: (id: string) => void;
  labelledBy?: string;
}) {
  return (
    <div role="tablist" aria-labelledby={labelledBy} className="flex flex-wrap gap-0 border-b border-slate-200">
      {tabs.map((tab) => {
        const selected = tab.id === value;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={selected}
            className={`min-h-9 px-3 text-sm font-medium ${
              selected
                ? "border-b-2 border-navy-800 text-navy-900"
                : "border-b-2 border-transparent text-ink-muted hover:text-navy-800"
            }`}
            onClick={() => onChange(tab.id)}
          >
            {tab.label}
          </button>
        );
      })}
    </div>
  );
}
