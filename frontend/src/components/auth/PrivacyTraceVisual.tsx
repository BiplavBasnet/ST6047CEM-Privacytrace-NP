import type { AuthMode } from "./AuthLayout";

const FLOW = [
  { title: "Detect", detail: "Flag sensitive values in API logs" },
  { title: "Mask", detail: "Keep raw data hidden while you work" },
  { title: "Trace", detail: "Link evidence to likely causes" },
  { title: "Verify", detail: "Confirm the fix after review" },
] as const;

export default function PrivacyTraceVisual({ mode }: { mode: AuthMode }) {
  const isLogin = mode === "login";

  return (
    <div className="auth-visual-panel relative flex h-full min-h-[30rem] flex-col justify-between overflow-hidden px-9 py-10 xl:px-11">
      <div className="auth-visual-glow pointer-events-none absolute inset-0" aria-hidden="true" />

      <header className="relative z-10 max-w-sm space-y-3">
        <p className="text-xs font-semibold uppercase tracking-wide text-teal-300/90">
          PrivacyTrace-NP
        </p>
        <h2 className="text-3xl font-semibold tracking-tight text-white">
          {isLogin ? "Investigate privacy risks in DFS APIs." : "Join the investigation workspace."}
        </h2>
        <p className="text-base leading-relaxed text-slate-300">
          Detect sensitive data in Nepal digital-finance API logs. Mask it. Trace the cause. Verify
          the fix.
        </p>
      </header>

      <div className="relative z-10 my-8" aria-hidden="true">
        <article className="auth-product-card overflow-hidden rounded-lg border border-white/10 bg-white/[0.04]">
          <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-teal-200/80">
                Sample incident
              </p>
              <p className="mt-0.5 text-sm font-medium text-white">API log · possible PII exposure</p>
            </div>
            <span className="auth-live-badge rounded px-2 py-1 text-xs font-semibold text-teal-50">
              In review
            </span>
          </div>

          <div className="space-y-3 px-4 py-4">
            <div className="grid grid-cols-[4.5rem_1fr] gap-x-3 gap-y-2 text-sm">
              <span className="text-slate-400">Phone</span>
              <span className="font-mono text-teal-100/90">98••••••21</span>
              <span className="text-slate-400">Account</span>
              <span className="font-mono text-teal-100/90">NP••••7F2A</span>
              <span className="text-slate-400">Source</span>
              <span className="text-slate-200">gateway access log</span>
            </div>

            <div className="auth-progress h-1 overflow-hidden rounded-full bg-white/10">
              <div className="auth-progress-bar h-full rounded-full bg-teal-400/80" />
            </div>
          </div>
        </article>

        <ol className="mt-5 space-y-0">
          {FLOW.map((step, index) => (
            <li key={step.title} className="auth-flow-row relative flex gap-3 pb-4 last:pb-0">
              {index < FLOW.length - 1 ? (
                <span className="auth-flow-connector absolute left-[0.55rem] top-5 bottom-0 w-px bg-teal-500/25" />
              ) : null}
              <span className={`auth-flow-dot auth-flow-dot-${index} relative z-[1] mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full`} />
              <div className="min-w-0">
                <p className="text-sm font-semibold text-white">{step.title}</p>
                <p className="text-sm text-slate-400">{step.detail}</p>
              </div>
            </li>
          ))}
        </ol>
      </div>

      <p className="relative z-10 text-xs leading-relaxed text-slate-400">
        Research prototype · masked evidence · role-based access
      </p>
    </div>
  );
}
