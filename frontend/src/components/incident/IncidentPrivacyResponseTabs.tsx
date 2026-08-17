import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { privacyResponseApi, type AffectedSubject, type BreachAlert, type PrivacyImpactResponse } from "../../api/privacyResponseClient";
import { useAuth } from "../../context/AuthContext";
import { sanitizeString } from "../../utils/safety";
import Card from "../Card";
import StatusBadge from "../StatusBadge";

type View = "impact" | "alerts" | "subjects";

export default function IncidentPrivacyResponseTabs({ incidentId }: { incidentId: string }) {
  const [params, setParams] = useSearchParams();
  const view = (params.get("privacy-view") as View) || "impact";
  const setView = (next: View) => setParams((current) => { current.set("privacy-view", next); return current; });
  return (
    <Card title="Privacy Response">
      <div role="tablist" aria-label="Privacy response views" className="mb-4 flex flex-wrap gap-2 border-b border-slate-200 pb-3">
        {(["impact", "alerts", "subjects"] as View[]).map((item) => (
          <button key={item} role="tab" aria-selected={view === item} className={view === item ? "btn-primary" : "btn-secondary"} onClick={() => setView(item)}>
            {item === "impact" ? "Privacy Impact" : item === "alerts" ? "Breach Alerts" : "Affected Customers"}
          </button>
        ))}
      </div>
      {view === "impact" ? <ImpactView incidentId={incidentId} /> : null}
      {view === "alerts" ? <AlertsView incidentId={incidentId} /> : null}
      {view === "subjects" ? <SubjectsView incidentId={incidentId} /> : null}
    </Card>
  );
}

function ImpactView({ incidentId }: { incidentId: string }) {
  const { can } = useAuth();
  const [data, setData] = useState<PrivacyImpactResponse | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => { try { setData(await privacyResponseApi.getImpact(incidentId)); setError(""); } catch (err) { setError(err instanceof Error ? err.message : "Privacy impact could not be loaded."); } }, [incidentId]);
  useEffect(() => { void load(); }, [load]);
  const run = async (action: () => Promise<unknown>) => { setBusy(true); setError(""); try { await action(); await load(); } catch (err) { setError(err instanceof Error ? err.message : "Action failed."); } finally { setBusy(false); } };
  if (!data && !error) return <p className="text-sm text-ink-muted">Loading privacy impact...</p>;
  const assessment = data?.assessment;
  return (
    <div data-testid="privacy-impact-panel">
      {error ? <p className="mb-3 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800">{sanitizeString(error)}</p> : null}
      {!assessment ? (
        <div className="flex items-center justify-between gap-3"><p className="text-sm text-ink-muted">No privacy impact assessment is recorded.</p>{can("privacy_impact:assess") ? <button className="btn-primary" disabled={busy} onClick={() => run(() => privacyResponseApi.assess(incidentId))}>Run assessment</button> : null}</div>
      ) : (
        <>
          <div className="grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
            <Metric label="Breach severity" value={`${assessment.breach_severity_level} (${assessment.breach_severity_score})`} />
            <Metric label="Potential privacy harm" value={`${assessment.privacy_harm_level} (${assessment.privacy_harm_score})`} />
            <Metric label="Likelihood / magnitude" value={`${assessment.harm_likelihood} / ${assessment.harm_magnitude}`} />
            <Metric label="Assessment confidence" value={assessment.assessment_confidence} />
            <Metric label="Affected subjects" value={assessment.affected_subject_count == null ? assessment.affected_subject_count_status : `${assessment.affected_subject_count} (${assessment.affected_subject_count_status})`} />
            <Metric label="Review state" value={assessment.status} />
          </div>
          {assessment.credential_exposure_present ? <p className="mt-4 rounded-md border border-red-200 bg-red-50 p-3 text-sm font-medium text-red-800">Credential exposure requires authorised containment review.</p> : null}
          {assessment.public_exposure_present ? <p className="mt-3 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">Public exposure is recorded in the reviewed assessment.</p> : null}
          <p className="mt-4 text-sm text-navy-900">Affected categories: {assessment.data_categories.map((item) => item.replaceAll("_", " ")).join(", ")}</p>
          <details className="mt-4 rounded-md border border-slate-200 p-3">
            <summary className="cursor-pointer text-sm font-semibold text-navy-700">Factor-by-factor explanation</summary>
            <div className="mt-3 space-y-3">
              {data?.factors.map((factor) => <div key={factor.id} className="border-b border-slate-100 pb-3 text-sm"><div className="flex flex-wrap items-center gap-2"><strong className="text-navy-900">{sanitizeString(factor.factor_label)}</strong><StatusBadge value={factor.review_status} /><span className="text-navy-900">Score {factor.score_contribution}</span></div><p className="mt-1 text-navy-900">{sanitizeString(factor.reason)}</p><p className="mt-1 text-xs text-ink-subtle">Evidence: {factor.evidence_ids.join(", ") || "Missing"}</p></div>)}
            </div>
          </details>
          {assessment.limitations.length ? <p className="mt-3 text-sm text-ink-muted">Limitations: {assessment.limitations.join("; ")}</p> : null}
          <div className="mt-4 flex flex-wrap gap-2">
            {can("privacy_impact:assess") && assessment.status === "draft" ? <button className="btn-primary" disabled={busy} onClick={() => run(() => privacyResponseApi.reviewAssessment(assessment.assessment_id, data?.factors.map((item) => item.id) ?? []))}>Complete assessment review</button> : null}
            {can("privacy_impact:approve") && assessment.status === "reviewed" ? <button className="btn-primary" disabled={busy} onClick={() => run(() => privacyResponseApi.approveAssessment(assessment.assessment_id))}>Approve assessment</button> : null}
            {can("privacy_impact:assess") ? <button className="btn-secondary" disabled={busy} onClick={() => run(() => privacyResponseApi.assess(incidentId))}>Reassess</button> : null}
          </div>
          <p className="mt-4 text-xs text-ink-subtle">{sanitizeString(data?.methodology_notice)}</p>
        </>
      )}
    </div>
  );
}

function AlertsView({ incidentId }: { incidentId: string }) {
  const { can } = useAuth();
  const [alerts, setAlerts] = useState<BreachAlert[]>([]);
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const load = useCallback(async () => { try { setAlerts((await privacyResponseApi.listAlerts(incidentId)).alerts); setError(""); } catch (err) { setError(err instanceof Error ? err.message : "Alerts could not be loaded."); } }, [incidentId]);
  useEffect(() => { void load(); }, [load]);
  const act = async (action: () => Promise<unknown>) => { try { await action(); await load(); } catch (err) { setError(err instanceof Error ? err.message : "Alert action failed."); } };
  return <div data-testid="breach-alerts-panel">{error ? <p className="mb-3 text-sm text-red-700">{sanitizeString(error)}</p> : null}{alerts.length ? <div className="space-y-3">{alerts.map((alert) => <article key={alert.alert_id} className="rounded-md border border-slate-200 p-4"><div className="flex flex-wrap items-center gap-2"><strong className="text-navy-900">{sanitizeString(alert.title)}</strong><StatusBadge value={alert.severity} /><StatusBadge value={alert.status} /></div><p className="mt-2 text-sm text-navy-900">{sanitizeString(alert.summary)}</p><p className="mt-1 text-xs text-ink-subtle">Reasons: {alert.reason_codes.join(", ")} | Triggered: {alert.triggered_at}</p>{can("breach_alert:manage") && !["resolved", "false_positive", "cancelled"].includes(alert.status) ? <div className="mt-3 flex flex-wrap gap-2"><button className="btn-secondary" onClick={() => act(() => privacyResponseApi.acknowledgeAlert(alert.alert_id))}>Acknowledge</button><input className="field-control min-w-64" aria-label={`False-positive reason for ${alert.alert_id}`} value={reasons[alert.alert_id] ?? ""} onChange={(event) => setReasons({ ...reasons, [alert.alert_id]: event.target.value })} placeholder="Reason required" /><button className="btn-secondary" disabled={(reasons[alert.alert_id] ?? "").trim().length < 10} onClick={() => act(() => privacyResponseApi.markFalsePositive(alert.alert_id, reasons[alert.alert_id]))}>Mark false positive</button></div> : null}</article>)}</div> : <p className="text-sm text-ink-muted">No breach alerts are linked to this incident.</p>}</div>;
}

function SubjectsView({ incidentId }: { incidentId: string }) {
  const [subjects, setSubjects] = useState<AffectedSubject[]>([]);
  const [error, setError] = useState("");
  useEffect(() => { privacyResponseApi.listSubjects(incidentId).then((result) => setSubjects(result.subjects)).catch((err) => setError(err instanceof Error ? err.message : "Affected customers could not be loaded.")); }, [incidentId]);
  return <div data-testid="affected-subjects-panel">{error ? <p className="text-sm text-red-700">{sanitizeString(error)}</p> : null}{subjects.length ? <div className="overflow-x-auto"><table className="data-table"><thead><tr><th>Customer reference</th><th>Data categories</th><th>Credential categories</th><th>Resolution</th><th>Notification</th></tr></thead><tbody>{subjects.map((item) => <tr key={item.subject_reference_id}><td className="mono-id">{item.subject_reference}</td><td className="text-navy-900">{item.affected_data_categories.join(", ")}</td><td className="text-navy-900">{item.credential_types.join(", ") || "None"}</td><td><StatusBadge value={item.resolution_status} /></td><td><StatusBadge value={item.notification_eligibility} /></td></tr>)}</tbody></table></div> : <p className="text-sm text-ink-muted">No pseudonymous affected-customer references are available.</p>}</div>;
}

function Metric({ label, value }: { label: string; value: string }) { return <div><p className="text-xs text-ink-subtle">{label}</p><p className="font-medium text-navy-900">{sanitizeString(value)}</p></div>; }
