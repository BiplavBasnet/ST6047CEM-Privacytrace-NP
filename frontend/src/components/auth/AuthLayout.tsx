import { Link } from "react-router-dom";
import type { ReactNode } from "react";
import PrivacyTraceVisual from "./PrivacyTraceVisual";

export type AuthMode = "login" | "signup";

export default function AuthLayout({
  mode,
  children,
}: {
  mode: AuthMode;
  children: ReactNode;
}) {
  return (
    <div className="auth-page flex min-h-[100dvh] items-center justify-center bg-surface px-4 py-8 sm:px-6">
      <div className="auth-shell grid w-full max-w-5xl overflow-hidden rounded-lg border border-slate-200 bg-white shadow-panel lg:grid-cols-2">
        <section className="flex flex-col justify-center px-6 py-8 sm:px-10 sm:py-10">
          <div className="mb-6">
            <Link
              to="/login"
              className="inline-flex items-center gap-2 text-navy-900 no-underline hover:text-accent"
            >
              <span
                className="flex h-9 w-9 items-center justify-center rounded-md bg-navy-800 text-sm font-bold text-white"
                aria-hidden="true"
              >
                PT
              </span>
              <span className="text-lg font-semibold tracking-tight text-navy-900">PrivacyTrace-NP</span>
            </Link>
          </div>
          {children}
        </section>
        <aside
          className="auth-visual relative hidden overflow-hidden bg-navy-900 text-white lg:flex lg:flex-col"
          aria-label="PrivacyTrace-NP finds and investigates sensitive data in digital finance API logs"
        >
          <PrivacyTraceVisual mode={mode} />
        </aside>
        <div className="border-t border-slate-100 px-6 py-4 lg:hidden">
          <p className="text-xs leading-relaxed text-ink-muted">
            Detect sensitive data in Nepal DFS API logs. Mask it. Trace the cause. Verify the fix.
          </p>
        </div>
      </div>
    </div>
  );
}
