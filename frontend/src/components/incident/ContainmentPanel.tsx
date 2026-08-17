import { useCallback, useEffect, useState } from "react";
import { privacyResponseApi, type ContainmentAction } from "../../api/privacyResponseClient";
import { useAuth } from "../../context/AuthContext";
import { sanitizeString } from "../../utils/safety";
import Card from "../Card";
import StatusBadge from "../StatusBadge";

export default function ContainmentPanel({ incidentId }: { incidentId: string }) {
  const { can } = useAuth();
  const [actions, setActions] = useState<ContainmentAction[]>([]);
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const load = useCallback(async () => { try { setActions((await privacyResponseApi.listContainment(incidentId)).actions); setError(""); } catch (err) { setError(err instanceof Error ? err.message : "Containment actions could not be loaded."); } }, [incidentId]);
  useEffect(() => { if (can("containment:read")) void load(); }, [can, load]);
  if (!can("containment:read")) return null;
  const act = async (action: () => Promise<unknown>) => { try { await action(); await load(); } catch (err) { setError(err instanceof Error ? err.message : "Containment action failed."); } };
  return (
    <Card title="Credential Containment">
      {error ? <p className="mb-3 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800">{sanitizeString(error)}</p> : null}
      {actions.length ? <div className="space-y-3">{actions.map((item) => {
        const reason = reasons[item.containment_action_id] ?? "";
        return <article key={item.containment_action_id} className="rounded-md border border-slate-200 p-4" data-testid="containment-action"><div className="flex flex-wrap items-center gap-2"><strong className="text-navy-900">{item.action_type.replaceAll("_", " ")}</strong><StatusBadge value={item.status} />{item.credential_type ? <span className="text-xs text-ink-muted">{item.credential_type}</span> : null}</div><p className="mt-2 text-sm text-navy-900">{sanitizeString(item.reason)}</p>{item.result_summary ? <p className="mt-2 text-sm text-ink-muted">Result: {sanitizeString(item.result_summary)}</p> : null}{item.failure_reason ? <p className="mt-1 text-sm text-red-700">Failure: {sanitizeString(item.failure_reason)}</p> : null}{(can("containment:approve") && item.status === "recommended") || (can("containment:execute") && item.status === "approved") ? <div className="mt-3 flex flex-wrap gap-2"><input className="field-control min-w-64" aria-label={`Containment reason for ${item.containment_action_id}`} value={reason} onChange={(event) => setReasons({ ...reasons, [item.containment_action_id]: event.target.value })} placeholder="Reason required" />{can("containment:approve") && item.status === "recommended" ? <button className="btn-primary" disabled={reason.trim().length < 10} onClick={() => act(() => privacyResponseApi.approveContainment(item.containment_action_id, reason))}>Approve containment</button> : null}{can("containment:execute") && item.status === "approved" ? <button className="btn-primary" disabled={reason.trim().length < 10} onClick={() => act(() => privacyResponseApi.executeContainment(item.containment_action_id, reason))}>Execute containment</button> : null}</div> : null}</article>;
      })}</div> : <p className="text-sm text-ink-muted">No credential containment action is recommended.</p>}
      <p className="mt-4 text-xs text-ink-subtle">Production credential providers are not connected; actions require approval and may remain manual.</p>
    </Card>
  );
}
