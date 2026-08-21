import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type IncidentSummary } from "../api/client";
import EmptyState from "../components/EmptyState";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
import { ErrorState, LoadingState } from "../components/LoadingError";
import { FilterBar, FilterField, QueueToolbar } from "../components/ui/primitives";
import { sanitizeString } from "../utils/safety";

const CLOSED_STATUSES = new Set(["closed", "resolved"]);
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

function needsAttention(incidents: IncidentSummary[]): IncidentSummary | null {
  const open = incidents.filter((item) => !CLOSED_STATUSES.has((item.status || "").toLowerCase()));
  if (!open.length) return null;
  return [...open].sort(
    (a, b) => (SEVERITY_RANK[(b.severity || "").toLowerCase()] ?? 0) - (SEVERITY_RANK[(a.severity || "").toLowerCase()] ?? 0),
  )[0];
}

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await api.listIncidents();
        if (!cancelled) setIncidents(data);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load incidents");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const filtered = incidents.filter((inc) => {
    if (severityFilter !== "all" && (inc.severity || "").toLowerCase() !== severityFilter) return false;
    if (statusFilter !== "all" && (inc.status || "").toLowerCase() !== statusFilter) return false;
    return true;
  });
  const attention = useMemo(() => needsAttention(incidents), [incidents]);

  return (
    <div className="space-y-6">
      <PageHeader
        breadcrumbs={[{ label: "Dashboard", to: "/" }, { label: "Incidents" }]}
        title="Incidents"
        description="Open an incident to review detections, evidence and reports."
        actions={
          <Link to="/live-monitor" className="btn-secondary">
            Open Live Monitor
          </Link>
        }
      />

      <FilterBar>
          <FilterField label="Severity" value={severityFilter} onChange={setSeverityFilter}>
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </FilterField>
          <FilterField label="Status" value={statusFilter} onChange={setStatusFilter}>
            <option value="all">All</option>
            <option value="new">New</option>
            <option value="investigating">Investigating</option>
            <option value="under_review">Under review</option>
            <option value="resolved">Resolved</option>
            <option value="closed">Closed</option>
          </FilterField>
        </FilterBar>

      {attention ? (
        <div
          data-testid="continue-flow"
          className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-slate-200 bg-white px-4 py-2.5"
        >
          <span className="text-sm text-ink-muted">Needs attention: {sanitizeString(attention.incident_id)}</span>
          <Link to={`/incidents/${attention.incident_id}`} className="text-sm font-semibold text-accent hover:text-teal-800">
            Next: Open incident →
          </Link>
        </div>
      ) : null}

      <div className="rounded-md border border-slate-200 bg-white p-4">
        <QueueToolbar countLabel={`${filtered.length} result${filtered.length === 1 ? "" : "s"}`} />
        <div className="mt-3">
          {loading ? <LoadingState message="Loading incidents…" /> : null}
          {error ? <ErrorState message={error} /> : null}
          {!loading && !error ? (
            filtered.length ? (
              <>
                <div className="overflow-x-auto">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Service</th>
                        <th>Endpoint</th>
                        <th className="text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.map((inc) => (
                        <tr key={inc.incident_id}>
                          <td>
                            <Link
                              to={`/incidents/${inc.incident_id}`}
                              className="mono-id text-accent hover:text-teal-800"
                            >
                              {inc.incident_id}
                            </Link>
                          </td>
                          <td className="font-medium text-navy-900">{sanitizeString(inc.title)}</td>
                          <td>
                            <StatusBadge value={inc.severity} />
                          </td>
                          <td>
                            <StatusBadge value={inc.status} />
                          </td>
                          <td className="text-sm text-ink-muted">
                            {sanitizeString(inc.affected_service ?? "—")}
                          </td>
                          <td className="max-w-[220px] truncate font-mono text-xs text-slate-600">
                            {sanitizeString(inc.affected_endpoint ?? "—")}
                          </td>
                          <td className="text-right">
                            <Link
                              to={`/incidents/${inc.incident_id}`}
                              className="text-xs font-semibold text-accent hover:text-teal-800"
                            >
                              Open
                            </Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            ) : (
              <EmptyState
                title="No incidents found."
                description="Open Live Monitor to create an incident from a privacy alert."
                action={
                  <Link to="/live-monitor" className="btn-primary">
                    Open Live Monitor
                  </Link>
                }
              />
            )
          ) : null}
        </div>
      </div>
    </div>
  );
}
