import { Link } from "react-router-dom";
import type { LiveAlert } from "../api/liveMonitorClient";
import { sanitizeString } from "../utils/safety";

export default function LiveAlertDetailPanel({
  alert,
  canCreateIncident,
  canDismiss,
  onCreateIncident,
  onDismiss,
}: {
  alert: LiveAlert | null;
  canCreateIncident: boolean;
  canDismiss: boolean;
  onCreateIncident: (alert: LiveAlert) => void;
  onDismiss: (alert: LiveAlert) => void;
}) {
  if (!alert) {
    return (
      <div className="flex min-h-[10rem] flex-col items-center justify-center px-4 py-8 text-center">
        <p className="text-sm font-medium text-navy-900">No alert selected</p>
        <p className="body-muted mt-1 max-w-sm">
          Choose an alert from the queue to view masked details.
        </p>
      </div>
    );
  }
  return (
    <div className="space-y-5 text-sm text-navy-900">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="font-mono text-xs text-ink-subtle">{sanitizeString(alert.alert_id)}</p>
          <h3 className="mt-1 text-base font-semibold text-navy-900">Masked alert detail</h3>
        </div>
        {/* One-click main action: create the incident, or open it if it exists. */}
        <div className="flex flex-wrap gap-2">
          {alert.linked_incident_id ? (
            <Link
              to={`/incidents/${encodeURIComponent(alert.linked_incident_id)}`}
              className="btn-primary"
            >
              Open Incident
            </Link>
          ) : canCreateIncident ? (
            <button
              type="button"
              onClick={() => onCreateIncident(alert)}
              className="btn-primary"
            >
              Create Incident
            </button>
          ) : null}
          {canDismiss && !alert.linked_incident_id && alert.status !== "dismissed_false_positive" ? (
            <button
              type="button"
              onClick={() => onDismiss(alert)}
              className="btn-secondary"
            >
              Dismiss false positive
            </button>
          ) : null}
        </div>
      </div>

      <p className="leading-6 text-ink-muted">{sanitizeString(alert.alert_summary)}</p>

      <dl className="grid border-t border-slate-100 sm:grid-cols-2">
        <Item label="Service" value={alert.service_name ?? "-"} />
        <Item label="Endpoint" value={alert.endpoint ?? "-"} mono />
        <Item label="Severity" value={alert.severity} />
        <Item label="Sensitive type" value={alert.sensitive_types.join(", ") || "-"} />
        <Item
          label="Exposure location"
          value={(alert.exposure_location ?? "unknown").replaceAll("_", " ")}
        />
        <Item
          label="Why unsafe / decision"
          value={
            alert.confidence_level
              ? `Policy-relevant exposure · confidence ${alert.confidence_level}${
                  alert.confidence_score != null
                    ? ` (${Math.round(alert.confidence_score * 100)}%)`
                    : ""
                }`
              : "Review required"
          }
        />
        <Item label="Masked value" value={alert.masked_values.join(", ") || "-"} mono />
        <Item label="First seen" value={alert.first_seen ?? alert.alert_time} />
        <Item label="Last seen" value={alert.last_seen ?? alert.updated_at} />
        <Item label="Repeat count" value={String(alert.repeat_count ?? 1)} />
      </dl>

      <p className="text-xs text-ink-muted">
        <span className="font-medium">Missing evidence:</span>{" "}
        {(alert.missing_metadata ?? []).map(sanitizeString).join(", ") || "None recorded"}
      </p>

      <p className="border-l-2 border-amber-400 bg-amber-50 px-3 py-2.5 text-xs leading-5 text-amber-900">
        Human review required: {alert.human_review_required ? "yes" : "no"}. This alert is symptom
        evidence only and cannot establish a high-confidence likely cause by itself.
      </p>
    </div>
  );
}

function Item({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0 border-b border-slate-100 py-3 sm:pr-4">
      <dt className="text-xs font-medium text-ink-subtle">{label}</dt>
      <dd className={`mt-1 break-words text-xs font-medium text-navy-900${mono ? " font-mono" : ""}`}>
        {sanitizeString(value)}
      </dd>
    </div>
  );
}
