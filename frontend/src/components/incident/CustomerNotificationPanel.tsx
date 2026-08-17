import { useCallback, useEffect, useState } from "react";
import { privacyResponseApi, type AffectedSubject, type CustomerNotification, type DeliveryStatus } from "../../api/privacyResponseClient";
import { useAuth } from "../../context/AuthContext";
import { sanitizeString } from "../../utils/safety";
import Card from "../Card";
import StatusBadge from "../StatusBadge";

export default function CustomerNotificationPanel({ incidentId }: { incidentId: string }) {
  const { can } = useAuth();
  const [notifications, setNotifications] = useState<CustomerNotification[]>([]);
  const [subjects, setSubjects] = useState<AffectedSubject[]>([]);
  const [sendingEnabled, setSendingEnabled] = useState(false);
  const [selectedSubject, setSelectedSubject] = useState("");
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [delivery, setDelivery] = useState<Record<string, DeliveryStatus>>({});
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    try {
      const [notificationResult, subjectResult] = await Promise.all([
        privacyResponseApi.listNotifications(incidentId), privacyResponseApi.listSubjects(incidentId),
      ]);
      setNotifications(notificationResult.notifications); setSendingEnabled(notificationResult.sending_enabled);
      setSubjects(subjectResult.subjects); setSelectedSubject((current) => current || subjectResult.subjects.find((item) => item.notification_eligibility === "eligible")?.subject_reference_id || "");
      setError("");
    } catch (err) { setError(err instanceof Error ? err.message : "Customer notifications could not be loaded."); }
  }, [incidentId]);
  useEffect(() => { if (can("customer_notification:read")) void load(); }, [can, load]);
  if (!can("customer_notification:read")) return null;
  const act = async (action: () => Promise<unknown>) => { try { await action(); await load(); } catch (err) { setError(err instanceof Error ? err.message : "Notification action failed."); } };
  const loadDelivery = async (id: string) => { try { setDelivery({ ...delivery, [id]: await privacyResponseApi.deliveryStatus(id) }); } catch (err) { setError(err instanceof Error ? err.message : "Delivery history could not be loaded."); } };
  return (
    <Card title="Customer Notification">
      {!sendingEnabled ? <p className="mb-4 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm font-medium text-amber-900">External customer notification sending is disabled.</p> : null}
      {error ? <p className="mb-3 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800">{sanitizeString(error)}</p> : null}
      {can("customer_notification:draft") ? <div className="mb-4 flex flex-wrap items-end gap-2"><label className="text-sm"><span className="mb-1 block text-xs text-ink-subtle">Eligible pseudonymous customer</span><select className="field-control min-w-72" value={selectedSubject} onChange={(event) => setSelectedSubject(event.target.value)}><option value="">No eligible subject</option>{subjects.filter((item) => item.notification_eligibility === "eligible").map((item) => <option key={item.subject_reference_id} value={item.subject_reference_id}>{item.subject_reference}</option>)}</select></label><button className="btn-primary" disabled={!selectedSubject} onClick={() => act(() => privacyResponseApi.draftNotification(incidentId, selectedSubject))}>Draft notification</button></div> : null}
      {notifications.length ? <div className="space-y-4">{notifications.map((item) => {
        const reason = reasons[item.notification_id] ?? "";
        const history = delivery[item.notification_id];
        return <article key={item.notification_id} className="rounded-md border border-slate-200 p-4" data-testid="customer-notification"><div className="flex flex-wrap items-center gap-2"><strong className="text-navy-900">{item.notification_id}</strong><StatusBadge value={item.recommendation} /><StatusBadge value={item.status} /></div><p className="mt-2 text-sm text-navy-900">{sanitizeString(item.decision_rationale)}</p><details className="mt-3 rounded-md bg-slate-50 p-3"><summary className="cursor-pointer text-sm font-semibold text-navy-700">Safe message preview</summary><p className="mt-2 whitespace-pre-wrap text-sm text-navy-900">{sanitizeString(item.draft_message)}</p></details>{((can("customer_notification:approve") && ["drafted", "approved"].includes(item.status)) || (can("customer_notification:queue") && item.status === "approved")) ? <div className="mt-3 flex flex-wrap gap-2"><input className="field-control min-w-64" aria-label={`Notification reason for ${item.notification_id}`} value={reason} onChange={(event) => setReasons({ ...reasons, [item.notification_id]: event.target.value })} placeholder="Decision reason" />{can("customer_notification:approve") && item.status === "drafted" ? <button className="btn-primary" disabled={reason.trim().length < 10} onClick={() => act(() => privacyResponseApi.approveNotification(item.notification_id, reason))}>Approve notification</button> : null}{can("customer_notification:approve") && ["drafted", "approved"].includes(item.status) ? <button className="btn-secondary" disabled={reason.trim().length < 10} onClick={() => act(() => privacyResponseApi.rejectNotification(item.notification_id, reason))}>Reject</button> : null}{can("customer_notification:queue") && item.status === "approved" ? <button className="btn-primary" disabled={!sendingEnabled} onClick={() => act(() => privacyResponseApi.queueNotification(item.notification_id, "email"))}>Queue email</button> : null}</div> : null}<button className="btn-secondary mt-3" onClick={() => loadDelivery(item.notification_id)}>Load delivery history</button>{history ? <div className="mt-3 text-sm text-ink-muted"><p>Outbox: {history.outbox.map((entry) => `${entry.channel} ${entry.status}`).join(", ") || "No queued delivery"}</p><p>Attempts: {history.attempts.map((attempt) => `${attempt.attempt_number} ${attempt.status}`).join(", ") || "None"}</p></div> : null}</article>;
      })}</div> : <p className="text-sm text-ink-muted">No customer notification decision is recorded.</p>}
    </Card>
  );
}
