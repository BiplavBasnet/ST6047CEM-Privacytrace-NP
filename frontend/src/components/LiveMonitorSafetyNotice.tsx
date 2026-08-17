export default function LiveMonitorSafetyNotice() {
  return (
    <p className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-ink-muted">
      Passively receives log/event copies; values are masked before display. Human review required.
    </p>
  );
}
