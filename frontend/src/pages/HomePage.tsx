import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, ArrowRight, Bell, Radio } from "lucide-react";
import { api, type HealthResponse, type IncidentSummary } from "../api/client";
import { liveMonitorApi, type LiveAlert, type LiveMonitorStatus } from "../api/liveMonitorClient";
import Card from "../components/Card";
import EmptyState from "../components/EmptyState";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
import { C, MetricCard } from "../components/ui/kit";
import { useAuth } from "../context/AuthContext";
import { sanitizeString } from "../utils/safety";

const CLOSED_STATUSES = new Set(["closed", "resolved"]);

function currentPriority(
  backendDown: boolean,
  alerts: LiveAlert[],
  incidents: IncidentSummary[],
): { title: string; detail: string; label: string; to: string; tone: "warning" | "active" | "normal" } {
  if (backendDown) {
    return {
      title: "Backend unavailable",
      detail: "Start the backend service, then reload this dashboard.",
      label: "Open User Guide",
      to: "/help/guide",
      tone: "warning",
    };
  }
  const unlinked = alerts.find((alert) => alert.status === "new" && !alert.linked_incident_id);
  if (unlinked) {
    return {
      title: "Unlinked privacy alert",
      detail: "Open the alert and create an incident.",
      label: "Open Alert Queue",
      to: "/alerts",
      tone: "warning",
    };
  }
  const active = incidents.find(
    (incident) => !CLOSED_STATUSES.has((incident.status || "").toLowerCase()),
  );
  if (active) {
    return {
      title: "Active investigation",
      detail: "Continue the incident workspace from its next ready step.",
      label: "Open Incident",
      to: `/incidents/${active.incident_id}`,
      tone: "active",
    };
  }
  return {
    title: "Monitor live event streams",
    detail: "Open Live Monitor and send a synthetic test event.",
    label: "Open Live Monitor",
    to: "/live-monitor",
    tone: "normal",
  };
}

export default function HomePage() {
  const { can } = useAuth();
  const canReadLive = can("live_monitor:read");
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState(false);
  const [monitor, setMonitor] = useState<LiveMonitorStatus | null>(null);
  const [alerts, setAlerts] = useState<LiveAlert[]>([]);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [nextActionLabel, setNextActionLabel] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const result = await api.getHealth();
        if (!cancelled) setHealth(result);
      } catch {
        if (!cancelled) setHealthError(true);
      }
      if (canReadLive) {
        try {
          const [status, alertList] = await Promise.all([
            liveMonitorApi.getStatus(),
            liveMonitorApi.listAlerts(),
          ]);
          if (!cancelled) {
            setMonitor(status);
            setAlerts(alertList.alerts);
          }
        } catch {
          // Operational cards remain available with empty values.
        }
      }
      try {
        const incidentList = await api.listIncidents();
        if (!cancelled) setIncidents(incidentList);
      } catch {
        // Empty state remains usable.
      }
      if (!cancelled) setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, [canReadLive]);

  const backendDown = healthError || (health ? health.status !== "healthy" : false);
  const openAlerts = alerts.filter((alert) => alert.status === "new").length;
  const activeIncidents = incidents.filter(
    (incident) => !CLOSED_STATUSES.has((incident.status || "").toLowerCase()),
  );
  const activeIncident = activeIncidents[0] ?? null;
  const awaitingReview = incidents.filter(
    (incident) => (incident.status || "").toLowerCase() === "under_review",
  ).length;
  const criticalHigh = alerts.filter((alert) => {
    const sev = (alert.severity || "").toLowerCase();
    return sev === "critical" || sev === "high";
  }).length;
  const priority = useMemo(
    () => currentPriority(backendDown, alerts, incidents),
    [alerts, backendDown, incidents],
  );

  useEffect(() => {
    if (!activeIncident) {
      setNextActionLabel(null);
      return;
    }
    let cancelled = false;
    api.getWorkflowState(activeIncident.incident_id)
      .then((workflow) => {
        if (!cancelled) setNextActionLabel(workflow.next_action.label);
      })
      .catch(() => {
        if (!cancelled) setNextActionLabel(null);
      });
    return () => {
      cancelled = true;
    };
  }, [activeIncident]);

  const monitorValue = backendDown
    ? "Offline"
    : !canReadLive
      ? "Restricted"
      : monitor
        ? monitor.running
          ? "Running"
          : "Stopped"
        : loading
          ? "Loading"
          : "Unknown";
  const lastEvent = monitor?.last_event_received_at ?? monitor?.last_alert_time;
  const substatus = backendDown
    ? "Backend unavailable"
    : `${monitorValue}${lastEvent ? ` · last event ${lastEvent}` : ""}`;
  const priorityTone = "border-slate-200";

  return (
    <div className="space-y-6 pt-fade-up">
      <PageHeader
        breadcrumbs={[{ label: "Dashboard" }]}
        title="Privacy operations"
        description={substatus}
      />

      <section
        data-testid="current-priority"
        className={`flex flex-wrap items-center justify-between gap-4 rounded-md border bg-white px-4 py-3 ${priorityTone}`}
      >
        <div className="min-w-0">
          <p className="eyebrow">Current priority</p>
          <h2 className="mt-1 text-lg font-semibold tracking-tight text-navy-900">{priority.title}</h2>
          <p className="body-muted mt-1">{priority.detail}</p>
        </div>
        <Link to={priority.to} className="btn-primary shrink-0">
          {priority.label}
          <ArrowRight size={15} />
        </Link>
      </section>

      <div className="flex flex-col divide-y divide-slate-200 overflow-hidden rounded-md border border-slate-200 bg-white sm:flex-row sm:divide-x sm:divide-y-0">
        <MetricCard label="Live Monitor" value={monitorValue} accent={C.teal} icon={<Radio size={16} />} />
        <MetricCard label="Open Alerts" value={openAlerts} accent={C.orange} icon={<Bell size={16} />} />
        <MetricCard label="Critical / high" value={criticalHigh} accent={C.red} icon={<AlertTriangle size={16} />} />
        <MetricCard
          label="Active Incidents"
          value={activeIncidents.length}
          accent={C.navy}
          icon={<AlertTriangle size={16} />}
        />
        <MetricCard label="Awaiting review" value={awaitingReview} accent={C.orange} icon={<Bell size={16} />} />
      </div>

      {canReadLive && alerts.length ? <QueueBars alerts={alerts} incidents={incidents} /> : null}

      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(280px,1fr)]">
        {canReadLive ? (
          <Card
            title="Latest alerts"
            actions={
              <Link to="/alerts" className="text-xs font-semibold text-accent hover:text-teal-800">
                View all
              </Link>
            }
          >
            {alerts.length ? (
              <div className="-mx-5 -mb-5 overflow-x-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Service</th>
                      <th>Endpoint</th>
                      <th>Severity</th>
                      <th>Status</th>
                      <th className="text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.slice(0, 5).map((alert) => (
                      <tr key={alert.alert_id}>
                        <td className="whitespace-nowrap text-xs text-ink-muted">
                          {sanitizeString(alert.first_seen ?? alert.alert_time)}
                        </td>
                        <td className="font-medium text-navy-900">{sanitizeString(alert.service_name ?? "-")}</td>
                        <td className="max-w-[220px] truncate font-mono text-xs text-slate-600">
                          {sanitizeString(alert.endpoint ?? "-")}
                        </td>
                        <td><StatusBadge value={alert.severity} /></td>
                        <td><StatusBadge value={alert.status} /></td>
                        <td className="text-right">
                          <Link
                            to={
                              alert.linked_incident_id
                                ? `/incidents/${alert.linked_incident_id}`
                                : `/live-monitor?alert=${encodeURIComponent(alert.alert_id)}`
                            }
                            className="text-xs font-semibold text-accent hover:text-teal-800"
                          >
                            {alert.linked_incident_id ? "Open Incident" : "Open Alert"}
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState
                title="No live alerts."
                description="Send a synthetic event from Live Monitor."
                action={<Link to="/live-monitor" className="text-sm font-semibold text-accent">Open Live Monitor</Link>}
              />
            )}
          </Card>
        ) : null}

        <Card title="Active incident">
          {activeIncident ? (
            <div data-testid="current-investigation" className="space-y-4">
              <div>
                <p className="font-mono text-xs text-ink-muted">{sanitizeString(activeIncident.incident_id)}</p>
                <Link
                  to={`/incidents/${activeIncident.incident_id}`}
                  className="mt-1 block text-base font-semibold text-navy-900 hover:text-accent"
                >
                  {sanitizeString(activeIncident.title ?? activeIncident.affected_service ?? "Privacy incident")}
                </Link>
              </div>
              <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-1 xl:grid-cols-2">
                <Summary label="Status" value={activeIncident.status} badge />
                <Summary label="Severity" value={activeIncident.severity} badge />
                <Summary label="Service" value={activeIncident.affected_service ?? "-"} />
                <Summary label="Next action" value={nextActionLabel ?? "See incident workspace"} />
              </dl>
            </div>
          ) : (
            <p className="text-sm text-ink-muted">No active incident.</p>
          )}
        </Card>
      </div>
    </div>
  );
}

function QueueBars({ alerts, incidents }: { alerts: LiveAlert[]; incidents: IncidentSummary[] }) {
  const severity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const alert of alerts) {
    const key = (alert.severity || "").toLowerCase();
    if (key in severity) severity[key as keyof typeof severity] += 1;
  }
  const types: Record<string, number> = {};
  for (const incident of incidents) {
    const key = (incident.status || "unknown").toLowerCase();
    types[key] = (types[key] ?? 0) + 1;
  }
  const sevMax = Math.max(1, ...Object.values(severity));
  const typeEntries = Object.entries(types).slice(0, 5);
  const typeMax = Math.max(1, ...typeEntries.map(([, count]) => count));
  return (
    <section className="rounded-md border border-slate-200 bg-white p-4" aria-label="Current queue">
      <p className="text-xs font-medium uppercase tracking-wide text-ink-subtle">Current queue</p>
      <div className="mt-3 grid gap-6 md:grid-cols-2">
        <BarList title="Alert severity" items={Object.entries(severity)} max={sevMax} />
        <BarList title="Incident status" items={typeEntries} max={typeMax} />
      </div>
    </section>
  );
}

function BarList({ title, items, max }: { title: string; items: [string, number][]; max: number }) {
  return (
    <div>
      <p className="text-sm font-semibold text-navy-900">{title}</p>
      <ul className="mt-2 space-y-1.5">
        {items.map(([label, count]) => (
          <li key={label} className="grid grid-cols-[7rem_1fr_2rem] items-center gap-2 text-xs">
            <span className="truncate text-ink-muted">{label.replaceAll("_", " ")}</span>
            <span className="h-1.5 overflow-hidden rounded-sm bg-slate-100">
              <span className="block h-full bg-navy-700" style={{ width: `${(count / max) * 100}%` }} />
            </span>
            <span className="text-right font-medium text-navy-900">{count}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Summary({ label, value, badge = false }: { label: string; value: string; badge?: boolean }) {
  return (
    <div>
      <dt className="text-xs text-ink-subtle">{label}</dt>
      <dd className="mt-1 text-sm font-medium text-navy-900">
        {badge ? <StatusBadge value={value} /> : sanitizeString(value)}
      </dd>
    </div>
  );
}
