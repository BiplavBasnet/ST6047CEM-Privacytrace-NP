import type { LiveAlert } from "../api/liveMonitorClient";
import StatusBadge from "./StatusBadge";
import RelativeTime from "./ui/primitives";
import { sanitizeString } from "../utils/safety";

export default function LiveAlertTable({
  alerts,
  selectedAlertId,
  onSelect,
}: {
  alerts: LiveAlert[];
  selectedAlertId?: string | null;
  onSelect: (alert: LiveAlert) => void;
}) {
  if (!alerts.length) {
    return (
      <div className="flex min-h-[10rem] flex-col items-center justify-center px-4 py-8 text-center">
        <p className="text-sm font-medium text-navy-900">No live alerts yet</p>
        <p className="body-muted mt-1 max-w-sm">
          Send a synthetic test event to populate this queue.
        </p>
      </div>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="data-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Sensitive type</th>
            <th>Exposure location</th>
            <th>Service</th>
            <th>Endpoint</th>
            <th>Confidence</th>
            <th>Severity</th>
            <th className="text-right">Action</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr
              key={alert.alert_id}
              className={selectedAlertId === alert.alert_id ? "bg-accent-soft/60" : undefined}
            >
              <td className="whitespace-nowrap text-xs text-ink-muted">
                <RelativeTime value={alert.first_seen ?? alert.alert_time} />
                {(alert.repeat_count ?? 1) > 1 ? (
                  <span className="ml-1 text-[10px] font-semibold text-ink-subtle">
                    ×{alert.repeat_count}
                  </span>
                ) : null}
              </td>
              <td className="max-w-[140px] truncate text-sm font-medium text-navy-900">
                {sanitizeString(alert.sensitive_types[0] ?? "-")}
              </td>
              <td className="max-w-[140px] truncate text-xs text-ink-muted">
                {sanitizeString((alert.exposure_location ?? "unknown").replaceAll("_", " "))}
              </td>
              <td className="font-medium text-navy-900">
                {sanitizeString(alert.service_name ?? "-")}
              </td>
              <td className="max-w-[180px] truncate font-mono text-xs text-slate-600">
                {sanitizeString(alert.endpoint ?? "-")}
              </td>
              <td>
                <span className="text-xs font-semibold capitalize text-navy-800">
                  {sanitizeString(alert.confidence_level ?? "—")}
                </span>
              </td>
              <td>
                <StatusBadge value={alert.severity} />
              </td>
              <td className="text-right">
                <button
                  type="button"
                  onClick={() => onSelect(alert)}
                  className="text-xs font-semibold text-accent hover:text-teal-800"
                >
                  Open Alert
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
