import type { ReactNode } from "react";
import StatusBadge from "../StatusBadge";

/**
 * Shared dashboard design-kit — navy + teal SaaS system.
 * Charts stay hand-rolled SVG; badges/status use shared Tailwind tokens.
 */

export const C = {
  navy: "#172826",
  navyDk: "#0f1f1d",
  teal: "#0f766e",
  orange: "#ea580c",
  red: "#dc2626",
  green: "#16a34a",
  violet: "#8b5cf6",
  border: "rgba(23,33,31,0.08)",
} as const;

export const shadowGlow = (color: string) =>
  `0 0 0 1px ${color}22, 0 4px 24px ${color}18, 0 1px 3px rgba(0,0,0,0.06)`;

export function Dot({ color, pulse = false }: { color: string; pulse?: boolean }) {
  return (
    <span className="relative inline-flex flex-shrink-0" style={{ width: 8, height: 8 }}>
      <span className="block h-2 w-2 rounded-full" style={{ background: color }} />
      {pulse ? (
        <span
          className="absolute inset-0 rounded-full"
          style={{ background: color, opacity: 0, animation: "ptPing 1.5s ease-out infinite" }}
        />
      ) : null}
    </span>
  );
}

export type BadgeVar =
  | "high" | "medium" | "low" | "teal" | "orange" | "red" | "navy" | "green" | "gray" | "amber";

const BADGE_VALUE: Record<BadgeVar, string> = {
  high: "high",
  medium: "medium",
  low: "low",
  teal: "monitoring",
  orange: "medium",
  red: "critical",
  navy: "investigating",
  green: "resolved",
  gray: "pending",
  amber: "medium",
};

export function Badge({
  v = "gray",
  children,
}: {
  v?: BadgeVar;
  dot?: boolean;
  children: ReactNode;
}) {
  return <StatusBadge value={typeof children === "string" ? children : BADGE_VALUE[v]} />;
}

const SEVERITY_TO_BADGE: Record<string, BadgeVar> = {
  critical: "red",
  high: "high",
  medium: "medium",
  low: "low",
};
export function severityBadge(sev: string): BadgeVar {
  return SEVERITY_TO_BADGE[sev.toLowerCase()] ?? "gray";
}

export { StatusBadge };

const STATUS_COLORS: Record<string, string> = {
  under_review: "#f97316",
  new: "#ef4444",
  open: "#ef4444",
  evidence_uploaded: "#3b82f6",
  masking_complete: "#14b8a6",
  confirmed_incident: "#8b5cf6",
  fix_verification: "#8b5cf6",
  report_pending: "#94a3b8",
  resolved: "#22c55e",
  closed: "#22c55e",
  monitoring: "#22c55e",
};
export function StatusDot({ status }: { status: string }) {
  const key = status.toLowerCase().replace(/[\s-]+/g, "_");
  const color = STATUS_COLORS[key] ?? "#94a3b8";
  const label = status.replace(/_/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-semibold" style={{ color }}>
      <Dot color={color} />
      {label}
    </span>
  );
}

export function MetricCard({
  label,
  value,
  icon,
  accent,
  sub,
  trend,
}: {
  label: string;
  value: string | number;
  icon: ReactNode;
  accent: string;
  sub?: string;
  trend?: string;
}) {
  return (
    <div
      data-testid="status-card"
      className="flex min-w-0 flex-1 items-center justify-between gap-3 px-4 py-3"
    >
      <div className="min-w-0">
        <span className="text-[11px] font-medium uppercase tracking-wider text-ink-subtle">{label}</span>
        <div
          className="mt-1 text-lg font-semibold leading-none tracking-tight text-navy-900"
          style={{ fontVariantNumeric: "tabular-nums" }}
        >
          {value}
        </div>
        {trend || sub ? (
          <div className="mt-1.5 flex items-center gap-2">
            {trend ? (
              <span
                className="inline-flex items-center gap-0.5 rounded px-1.5 py-0.5 text-xs font-semibold"
                style={{ background: `${accent}15`, color: accent }}
              >
                {trend}
              </span>
            ) : null}
            {sub ? <span className="text-xs text-ink-subtle">{sub}</span> : null}
          </div>
        ) : null}
      </div>
      <div className="flex h-7 w-7 shrink-0 items-center justify-center text-current" style={{ color: accent }}>
        {icon}
      </div>
    </div>
  );
}

export function StepBar({ steps, current }: { steps: string[]; current: number }) {
  return (
    <div className="flex items-start">
      {steps.map((s, i) => (
        <div key={s} className="flex min-w-0 flex-1 items-center">
          <div className="flex flex-shrink-0 flex-col items-center gap-1">
            <div
              className={[
                "flex h-6 w-6 items-center justify-center rounded-full border-2 text-xs font-bold",
                i < current
                  ? "border-accent bg-accent text-white"
                  : i === current
                    ? "border-navy-800 bg-navy-800 text-white"
                    : "border-slate-200 bg-white text-slate-400",
              ].join(" ")}
            >
              {i < current ? "✓" : i + 1}
            </div>
            <div
              className={[
                "whitespace-nowrap text-xs font-medium",
                i === current ? "text-navy-900" : i < current ? "text-accent" : "text-slate-400",
              ].join(" ")}
            >
              {s}
            </div>
          </div>
          {i < steps.length - 1 ? (
            <div
              className={[
                "mx-1 mb-[14px] h-[2px] flex-1",
                i < current ? "bg-accent" : "bg-slate-200",
              ].join(" ")}
            />
          ) : null}
        </div>
      ))}
    </div>
  );
}

// ─── Arc gauge ─────────────────────────────────────────────────────────────────
export function ArcGauge({ score }: { score: number }) {
  const cx = 90, cy = 90, R = 70, start = -210, total = 240;
  const rad = (d: number) => (d * Math.PI) / 180;
  const pt = (deg: number) => ({
    x: cx + R * Math.cos(rad(start + deg)),
    y: cy + R * Math.sin(rad(start + deg)),
  });
  const clamped = Math.max(0, Math.min(100, score));
  const p0 = pt(0), pT = pt(total), pF = pt(total * (clamped / 100));
  const lT = total > 180 ? 1 : 0;
  const lF = total * (clamped / 100) > 180 ? 1 : 0;
  const color = clamped >= 70 ? C.red : clamped >= 40 ? C.orange : C.teal;
  const label = clamped >= 70 ? "High Risk" : clamped >= 40 ? "Moderate" : "Low Risk";
  return (
    <svg viewBox="0 0 180 140" width="100%" style={{ maxWidth: 180 }}>
      <path
        d={`M${p0.x},${p0.y} A${R},${R} 0 ${lT},1 ${pT.x},${pT.y}`}
        fill="none"
        stroke="rgba(255,255,255,0.12)"
        strokeWidth="12"
        strokeLinecap="round"
      />
      {clamped > 0 ? (
        <path
          d={`M${p0.x},${p0.y} A${R},${R} 0 ${lF},1 ${pF.x},${pF.y}`}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 8px ${color}88)` }}
        />
      ) : null}
      <text x={cx} y={cy + 8} textAnchor="middle" fontSize="32" fontWeight="700" fill="#fff" fontFamily="Inter, system-ui, sans-serif">
        {clamped}
      </text>
      <text x={cx} y={cy + 24} textAnchor="middle" fontSize="12" fontWeight="600" fill={color} fontFamily="Inter, system-ui, sans-serif">
        {label}
      </text>
      <text x={pt(0).x - 4} y={pt(0).y + 4} textAnchor="end" fontSize="11" fill="rgba(255,255,255,0.45)" fontFamily="Inter, system-ui, sans-serif">0</text>
      <text x={pt(total).x + 4} y={pt(total).y + 4} textAnchor="start" fontSize="11" fill="rgba(255,255,255,0.45)" fontFamily="Inter, system-ui, sans-serif">100</text>
    </svg>
  );
}

// ─── Donut ─────────────────────────────────────────────────────────────────────
export type DonutSlice = { name: string; v: number; color: string };
export function Donut({ data }: { data: DonutSlice[] }) {
  const total = data.reduce((a, d) => a + d.v, 0);
  const cx = 48, cy = 48, R = 38, r = 25;
  let angle = -Math.PI / 2;
  const slices =
    total === 0
      ? []
      : data
          .filter((d) => d.v > 0)
          .map((d) => {
            const sweep = (d.v / total) * 2 * Math.PI - 0.05;
            const p = `M${cx + R * Math.cos(angle)},${cy + R * Math.sin(angle)} A${R},${R} 0 ${
              sweep > Math.PI ? 1 : 0
            },1 ${cx + R * Math.cos(angle + sweep)},${cy + R * Math.sin(angle + sweep)} L${
              cx + r * Math.cos(angle + sweep)
            },${cy + r * Math.sin(angle + sweep)} A${r},${r} 0 ${sweep > Math.PI ? 1 : 0},0 ${
              cx + r * Math.cos(angle)
            },${cy + r * Math.sin(angle)} Z`;
            angle += sweep + 0.05;
            return { p, color: d.color };
          });
  return (
    <svg viewBox="0 0 96 96" width={96} height={96}>
      {total === 0 ? (
        <circle cx={cx} cy={cy} r={(R + r) / 2} fill="none" stroke="#e2e8f0" strokeWidth={R - r} />
      ) : (
        slices.map((s, i) => (
          <path key={i} d={s.p} fill={s.color} style={{ filter: `drop-shadow(0 2px 4px ${s.color}44)` }} />
        ))
      )}
      <text x={cx} y={cy + 5} textAnchor="middle" fontSize="18" fontWeight="700" fill="#172826" fontFamily="Inter, system-ui, sans-serif">
        {total}
      </text>
      <text x={cx} y={cy + 17} textAnchor="middle" fontSize="11" fill="#87938f" fontFamily="Inter, system-ui, sans-serif">open</text>
    </svg>
  );
}

// ─── Sparkline (area line) ─────────────────────────────────────────────────────
export type SparkPoint = { day: string; v: number };
export function Sparkline({ data }: { data: SparkPoint[] }) {
  const W = 600, H = 130, pad = { t: 8, r: 8, b: 28, l: 28 };
  const max = Math.max(8, ...data.map((d) => d.v));
  const cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;
  const n = Math.max(1, data.length - 1);
  const xs = data.map((_, i) => pad.l + (i / n) * cw);
  const ys = data.map((d) => pad.t + ch - (d.v / max) * ch);
  const line = xs.map((x, i) => `${i === 0 ? "M" : "L"}${x},${ys[i]}`).join(" ");
  const area = `${line} L${xs[xs.length - 1] ?? pad.l},${pad.t + ch} L${xs[0] ?? pad.l},${pad.t + ch} Z`;
  const ticks = [0, max / 4, max / 2, (3 * max) / 4, max].map((t) => Math.round(t));
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: H }} preserveAspectRatio="none">
      <defs>
        <linearGradient id="ptSpark" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={C.teal} stopOpacity=".18" />
          <stop offset="100%" stopColor={C.teal} stopOpacity="0" />
        </linearGradient>
      </defs>
      {ticks.map((t, i) => {
        const y = pad.t + ch - (t / max) * ch;
        return <line key={i} x1={pad.l} x2={W - pad.r} y1={y} y2={y} stroke="#e2e8f0" strokeWidth="1" />;
      })}
      {data.length > 1 ? <path d={area} fill="url(#ptSpark)" /> : null}
      {data.length > 1 ? (
        <path d={line} fill="none" stroke={C.teal} strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round" />
      ) : null}
      {xs.map((x, i) => (
        <circle key={i} cx={x} cy={ys[i]} r="4" fill="#fff" stroke={C.teal} strokeWidth="2.5" />
      ))}
      {data.map((d, i) => (
        <text key={i} x={xs[i]} y={H - 6} textAnchor="middle" fontSize="11" fill="#87938f" fontFamily="Inter, system-ui, sans-serif">
          {d.day}
        </text>
      ))}
    </svg>
  );
}
