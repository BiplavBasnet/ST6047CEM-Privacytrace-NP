import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { alertOperationsApi, type OperationalBreachAlert } from "../../api/alertOperationsClient";
import { useAuth } from "../../context/AuthContext";
import { sanitizeString } from "../../utils/safety";
import Card from "../Card";
import StatusBadge from "../StatusBadge";

export default function BreachAlertOperationsPanel() {
  const { can } = useAuth();
  const [alerts, setAlerts] = useState<OperationalBreachAlert[]>([]);
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const load = useCallback(async () => { if (!can("alert_operations:read")) return; try { setAlerts((await alertOperationsApi.list()).alerts); setError(""); } catch (err) { setError(err instanceof Error ? err.message : "Operational alerts could not be loaded."); } }, [can]);
  useEffect(() => { void load(); }, [load]);
  const act = async (action: () => Promise<unknown>) => { try { await action(); await load(); } catch (err) { setError(err instanceof Error ? err.message : "Alert action failed."); } };
  if (!can("alert_operations:read")) return null;
  return <Card title="Assessed Breach Alert Operations" actions={<span className="text-xs text-ink-subtle">{alerts.length} alerts</span>}>{error ? <p className="mb-3 text-sm text-red-700">{sanitizeString(error)}</p> : null}{alerts.length ? <div className="space-y-3">{alerts.map((alert) => { const reason = reasons[alert.alert_id] ?? "Reviewed operational alert state and supporting evidence."; return <article key={alert.alert_id} className="rounded-md border border-slate-200 p-4"><div className="flex flex-wrap items-center gap-2"><Link className="font-semibold text-accent" to={`/incidents/${encodeURIComponent(alert.incident_id)}`}>{sanitizeString(alert.title)}</Link><StatusBadge value={alert.severity} /><StatusBadge value={alert.status} />{alert.overdue ? <StatusBadge value="overdue" /> : null}</div><p className="mt-2 text-sm text-navy-900">{sanitizeString(alert.summary)}</p><p className="mt-1 text-xs text-ink-subtle">Occurrences: {alert.occurrence_count} | Escalation: {alert.escalation_level.replaceAll("_", " ")} | Team: {sanitizeString(alert.assigned_team ?? "Unassigned")}</p>{can("alert_operations:manage") ? <><input className="field-control mt-3 w-full" aria-label={`Operational reason for ${alert.alert_id}`} value={reasons[alert.alert_id] ?? ""} onChange={(event) => setReasons({ ...reasons, [alert.alert_id]: event.target.value })} placeholder="Auditable reason (optional default provided)" /><div className="mt-3 flex flex-wrap gap-2"><button className="btn-secondary" onClick={() => act(() => alertOperationsApi.assign(alert.alert_id, "privacy-response", reason))}>Assign team</button>{alert.suppression_reason ? <button className="btn-secondary" onClick={() => act(() => alertOperationsApi.unsuppress(alert.alert_id, reason))}>Unsuppress</button> : <button className="btn-secondary" onClick={() => act(() => alertOperationsApi.suppress(alert.alert_id, reason))}>Suppress</button>}<button className="btn-secondary" onClick={() => act(() => alertOperationsApi.escalate(alert.alert_id, reason))}>Escalate</button>{["resolved", "false_positive", "cancelled"].includes(alert.status) ? <button className="btn-secondary" onClick={() => act(() => alertOperationsApi.reopen(alert.alert_id, reason))}>Reopen</button> : null}</div></> : null}</article>; })}</div> : <p className="text-sm text-ink-muted">No assessed breach alerts are available.</p>}</Card>;
}
