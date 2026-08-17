import { useEffect, useState } from "react";
import { alertOperationsApi, type AlertMetrics } from "../../api/alertOperationsClient";
import { useAuth } from "../../context/AuthContext";
import Card from "../Card";

export default function AlertOperationsMetricsPanel() {
  const { can } = useAuth();
  const [metrics, setMetrics] = useState<AlertMetrics | null>(null);
  const [error, setError] = useState("");
  useEffect(() => { if (can("alert_operations:read")) alertOperationsApi.metrics().then(setMetrics).catch((err) => setError(err instanceof Error ? err.message : "Alert metrics could not be loaded.")); }, [can]);
  if (!can("alert_operations:read")) return null;
  return <Card title="Breach Alert Operations">{error ? <p className="text-sm text-red-700">{error}</p> : metrics ? <div className="grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-4"><Metric label="Active alerts" value={metrics.active_alerts} /><Metric label="Duplicates prevented" value={metrics.duplicate_alerts_prevented} /><Metric label="Past acknowledgement deadline" value={metrics.unacknowledged_past_deadline} /><Metric label="Escalated / reopened" value={`${metrics.escalated_alerts} / ${metrics.reopened_alerts}`} /></div> : <p className="text-sm text-ink-muted">Loading alert metrics...</p>}<p className="mt-3 text-xs text-ink-subtle">Operational counts contain no customer values, destinations, credentials, or AML investigation details.</p></Card>;
}

function Metric({ label, value }: { label: string; value: string | number }) { return <div><p className="text-xs text-ink-subtle">{label}</p><p className="font-semibold text-navy-900">{value}</p></div>; }
