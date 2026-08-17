import { useEffect, useMemo, useState } from "react";
import { api, type AuditLog } from "../api/client";
import Card from "../components/Card";
import DetailInspector from "../components/DetailInspector";
import EmptyState from "../components/EmptyState";
import PageHeader from "../components/PageHeader";
import PermissionDenied from "../components/PermissionDenied";
import { ErrorState, LoadingState } from "../components/LoadingError";
import { useAuth } from "../context/AuthContext";
import { sanitizeString } from "../utils/safety";

/**
 * Governance view of recent audit log entries. Read-only; shows action,
 * target and timestamp only — no payloads and no sensitive values.
 */
export default function AuditLogsPage() {
  const { can } = useAuth();
  const allowed = can("audit:read");
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<AuditLog | null>(null);

  useEffect(() => {
    if (!allowed) return;
    let cancelled = false;
    (async () => {
      try {
        const data = await api.listAllAuditLogs(50);
        if (!cancelled) setLogs(data.logs);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load audit logs");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [allowed]);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return logs;
    return logs.filter((log) =>
      [log.action, log.target_type, log.target_id].join(" ").toLowerCase().includes(needle),
    );
  }, [logs, query]);

  if (!allowed) {
    return (
      <PermissionDenied
        title="Audit logs are restricted"
        requiredHint="auditor, security analyst or admin"
        stillCanDo="You can still view the dashboard and incidents."
      />
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        breadcrumbs={[{ label: "Dashboard", to: "/" }, { label: "Audit Logs" }]}
        title="Audit Logs"
        description="Recent recorded actions across the investigation workflow."
      />
      <Card title="Recent activity">
        <label className="mb-3 block max-w-sm text-sm text-navy-900">
          Search
          <input
            className="field-control mt-1 w-full"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Action or target"
          />
        </label>
        {loading ? <LoadingState message="Loading audit logs…" /> : null}
        {error ? <ErrorState message={error} /> : null}
        {!loading && !error ? (
          logs.length ? (
            visible.length ? (
            <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(260px,18rem)]">
            <div className="-mx-5 -mb-5 overflow-x-auto sm:-mx-6">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Action</th>
                    <th>Target</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((log) => (
                    <tr
                      key={log.id}
                      className={`cursor-pointer ${selected?.id === log.id ? "is-selected" : ""}`}
                      aria-selected={selected?.id === log.id}
                      onClick={() => setSelected(log)}
                    >
                      <td className="text-xs text-ink-muted">
                        {sanitizeString(log.timestamp)}
                      </td>
                      <td className="font-medium text-navy-900">{sanitizeString(log.action)}</td>
                      <td className="text-xs text-ink-muted">
                        {sanitizeString(
                          [log.target_type, log.target_id].filter(Boolean).join(" · ") || "—",
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <DetailInspector title="Audit entry" onClose={selected ? () => setSelected(null) : undefined}>
              {selected ? (
                <dl className="space-y-2 text-sm">
                  <div>
                    <dt className="text-xs text-ink-subtle">Time</dt>
                    <dd>{sanitizeString(selected.timestamp)}</dd>
                  </div>
                  <div>
                    <dt className="text-xs text-ink-subtle">Action</dt>
                    <dd className="font-medium text-navy-900">{sanitizeString(selected.action)}</dd>
                  </div>
                  <div>
                    <dt className="text-xs text-ink-subtle">Target</dt>
                    <dd>{sanitizeString([selected.target_type, selected.target_id].filter(Boolean).join(" · ") || "—")}</dd>
                  </div>
                  <div>
                    <dt className="text-xs text-ink-subtle">Entry ID</dt>
                    <dd className="font-mono text-[11px]">{sanitizeString(String(selected.id))}</dd>
                  </div>
                </dl>
              ) : (
                <p className="text-sm text-ink-muted">Select a row. Payloads are not shown.</p>
              )}
            </DetailInspector>
            </div>
            ) : (
              <EmptyState title="No matching audit entries." description="Try a different search." />
            )
          ) : (
            <EmptyState
              title="No audit entries yet."
              description="Actions such as evidence uploads, reviews and report exports are recorded here."
            />
          )
        ) : null}
      </Card>
    </div>
  );
}
