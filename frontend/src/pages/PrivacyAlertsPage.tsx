import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { liveMonitorApi, type LiveAlert } from "../api/liveMonitorClient";
import Card from "../components/Card";
import CollapsibleSection from "../components/CollapsibleSection";
import DetailInspector from "../components/DetailInspector";
import EmptyState from "../components/EmptyState";
import LiveAlertDetailPanel from "../components/LiveAlertDetailPanel";
import PageHeader from "../components/PageHeader";
import PermissionDenied from "../components/PermissionDenied";
import StatusBadge from "../components/StatusBadge";
import BreachAlertOperationsPanel from "../components/incident/BreachAlertOperationsPanel";
import { ErrorState, LoadingState } from "../components/LoadingError";
import RelativeTime, { FilterBar, FilterField, QueueToolbar } from "../components/ui/primitives";
import { useAuth } from "../context/AuthContext";
import { sanitizeString } from "../utils/safety";

export default function PrivacyAlertsPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const allowed = can("live_monitor:read");
  const canCreateIncident = can("live_monitor:incident");
  const canDismiss = can("live_monitor:dismiss");
  const [alerts, setAlerts] = useState<LiveAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [linkFilter, setLinkFilter] = useState("all");
  const [serviceFilter, setServiceFilter] = useState("all");
  const [endpointFilter, setEndpointFilter] = useState("all");
  const [selected, setSelected] = useState<LiveAlert | null>(null);

  useEffect(() => {
    if (!allowed) return;
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await liveMonitorApi.listAlerts();
        if (!cancelled) setAlerts(data.alerts);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load alerts");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [allowed]);

  const services = useMemo(
    () => [...new Set(alerts.map((alert) => alert.service_name).filter(Boolean))] as string[],
    [alerts],
  );
  const endpoints = useMemo(
    () => [...new Set(alerts.map((alert) => alert.endpoint).filter(Boolean))] as string[],
    [alerts],
  );
  const filtered = useMemo(
    () =>
      alerts.filter((alert) => {
        if (statusFilter !== "all" && alert.status !== statusFilter) return false;
        if (severityFilter !== "all" && alert.severity !== severityFilter) return false;
        if (linkFilter === "linked" && !alert.linked_incident_id) return false;
        if (linkFilter === "unlinked" && alert.linked_incident_id) return false;
        if (serviceFilter !== "all" && alert.service_name !== serviceFilter) return false;
        if (endpointFilter !== "all" && alert.endpoint !== endpointFilter) return false;
        return true;
      }),
    [alerts, endpointFilter, linkFilter, serviceFilter, severityFilter, statusFilter],
  );

  if (!allowed) {
    return (
      <PermissionDenied
        title="Alerts are restricted"
        requiredHint="security analyst, DevSecOps engineer or admin"
        stillCanDo="You can still view incidents and reports."
      />
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        breadcrumbs={[{ label: "Dashboard", to: "/" }, { label: "Alerts" }]}
        title="Privacy alerts"
        description={`${alerts.filter((alert) => alert.status === "new").length} active in the current queue.`}
        actions={
          <Link to="/live-monitor" className="btn-secondary">
            Open Live Monitor
          </Link>
        }
      />

      <div>
        <FilterBar>
          <FilterField label="Status" value={statusFilter} onChange={setStatusFilter}>
            <option value="all">All</option>
            <option value="new">New</option>
            <option value="linked_to_incident">Linked</option>
            <option value="dismissed_false_positive">Dismissed</option>
          </FilterField>
          <FilterField label="Severity" value={severityFilter} onChange={setSeverityFilter}>
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </FilterField>
          <FilterField label="Linked / Unlinked" value={linkFilter} onChange={setLinkFilter}>
            <option value="all">All</option>
            <option value="unlinked">Unlinked</option>
            <option value="linked">Linked</option>
          </FilterField>
        </FilterBar>
        <details className="mt-4 border-t border-slate-100 pt-3 text-sm" data-testid="more-alert-filters">
          <summary className="cursor-pointer text-xs font-semibold text-accent">More filters</summary>
          <div className="mt-3">
            <FilterBar className="lg:grid-cols-2">
              <FilterField label="Service" value={serviceFilter} onChange={setServiceFilter}>
                <option value="all">All</option>
                {services.map((service) => (
                  <option key={service} value={service}>
                    {service}
                  </option>
                ))}
              </FilterField>
              <FilterField label="Endpoint" value={endpointFilter} onChange={setEndpointFilter}>
                <option value="all">All</option>
                {endpoints.map((endpoint) => (
                  <option key={endpoint} value={endpoint}>
                    {endpoint}
                  </option>
                ))}
              </FilterField>
            </FilterBar>
          </div>
        </details>
      </div>

      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(320px,22rem)]">
      <Card title="Alerts">
        <QueueToolbar
          countLabel={`${filtered.length} result${filtered.length === 1 ? "" : "s"}`}
        />
        <div className="mt-3">
          {loading ? <LoadingState message="Loading alerts..." /> : null}
          {error ? <ErrorState message={error} /> : null}
          {!loading && !error ? (
            filtered.length ? (
              <div className="-mx-5 -mb-5 overflow-x-auto sm:-mx-6">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Service</th>
                      <th>Endpoint</th>
                      <th>Severity</th>
                      <th>Status</th>
                      <th>Linked Incident</th>
                      <th className="text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((alert) => (
                      <tr
                        key={alert.alert_id}
                        className={`${alert.status === "new" ? "bg-accent-soft/30" : ""} ${selected?.alert_id === alert.alert_id ? "is-selected" : ""} cursor-pointer`}
                        aria-selected={selected?.alert_id === alert.alert_id}
                        onClick={() => setSelected(alert)}
                      >
                        <td className="whitespace-nowrap text-xs text-ink-muted">
                          <RelativeTime value={alert.first_seen ?? alert.alert_time} />
                        </td>
                        <td className="font-medium text-navy-900">
                          {sanitizeString(alert.service_name ?? "-")}
                        </td>
                        <td className="max-w-[260px] truncate font-mono text-xs text-slate-600">
                          {sanitizeString(alert.endpoint ?? "-")}
                        </td>
                        <td>
                          <StatusBadge value={alert.severity} />
                        </td>
                        <td>
                          <StatusBadge value={alert.status} />
                        </td>
                        <td>
                          {alert.linked_incident_id ? (
                            <Link
                              to={`/incidents/${encodeURIComponent(alert.linked_incident_id)}`}
                              className="mono-id text-accent hover:text-teal-800"
                            >
                              {sanitizeString(alert.linked_incident_id)}
                            </Link>
                          ) : (
                            <span className="text-xs text-slate-400">Unlinked</span>
                          )}
                        </td>
                        <td className="text-right">
                          <Link
                            to={
                              alert.linked_incident_id
                                ? `/incidents/${encodeURIComponent(alert.linked_incident_id)}`
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
                title="No alerts match these filters."
                description="Adjust the filters or send a synthetic event."
                action={
                  <Link to="/live-monitor" className="btn-secondary">
                    Open Live Monitor
                  </Link>
                }
              />
            )
          ) : null}
        </div>
      </Card>
      <DetailInspector title="Alert detail" onClose={selected ? () => setSelected(null) : undefined}>
        <LiveAlertDetailPanel
          alert={selected}
          canCreateIncident={canCreateIncident}
          canDismiss={canDismiss}
          onCreateIncident={(alert) => {
            void liveMonitorApi.createIncident(alert.alert_id).then((result) => {
              if (result.incident_id) navigate(`/incidents/${encodeURIComponent(result.incident_id)}/overview`);
            });
          }}
          onDismiss={(alert) => {
            void liveMonitorApi.dismissAlert(alert.alert_id).then(() => {
              setAlerts((current) => current.filter((item) => item.alert_id !== alert.alert_id));
              setSelected(null);
            });
          }}
        />
      </DetailInspector>
      </div>
      <CollapsibleSection summary="Alert operations">
        <BreachAlertOperationsPanel />
      </CollapsibleSection>
    </div>
  );
}
