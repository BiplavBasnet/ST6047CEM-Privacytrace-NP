import type { LiveMonitorStatus } from "../api/liveMonitorClient";
import { sanitizeString } from "../utils/safety";

export default function LiveMonitorStatusCard({ status }: { status: LiveMonitorStatus | null }) {
  if (!status) {
    return <p className="text-sm text-slate-600">Status is not loaded yet.</p>;
  }
  return (
    <dl className="grid divide-y divide-slate-100 sm:grid-cols-2 sm:divide-x sm:divide-y-0 lg:grid-cols-4">
      <Metric label="State" value={status.running ? "Running" : "Stopped"} />
      <Metric label="Events received" value={String(status.event_count ?? 0)} />
      <Metric label="Alerts created" value={String(status.alert_count)} />
      <Metric label="Last event" value={status.last_event_received_at ?? "None"} />
    </dl>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 px-4 py-3 first:pl-0 last:pr-0">
      <dt className="text-xs font-medium text-ink-subtle">{label}</dt>
      <dd className="mt-1.5 break-words text-sm font-semibold text-navy-900">{sanitizeString(value)}</dd>
    </div>
  );
}
