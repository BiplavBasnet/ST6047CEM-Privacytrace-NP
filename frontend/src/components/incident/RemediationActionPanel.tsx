import { useEffect, useState, type FormEvent } from "react";
import {
  api,
  type RemediationAction,
  type RemediationActionInput,
} from "../../api/client";
import StatusBadge from "../StatusBadge";
import { sanitizeString } from "../../utils/safety";

const ACTION_TYPES = [
  "logging_middleware_change",
  "redaction_rule_update",
  "configuration_change",
  "debug_logging_disable",
  "proxy_logging_change",
  "apm_logging_change",
  "authorization_logging_change",
  "application_code_change",
  "dependency_update",
  "other",
];
const STATUSES = [
  "not_started",
  "assigned",
  "in_progress",
  "awaiting_retest",
  "completed",
  "cancelled",
];

const EMPTY: RemediationActionInput = {
  action_type: "redaction_rule_update",
  action_description: "",
  affected_component: "",
  assigned_owner: "",
  status: "not_started",
  priority: "medium",
  target_date: null,
  retest_required: true,
  completion_notes: null,
};

export default function RemediationActionPanel({
  incidentId,
  actions,
  available,
  blockedReason,
  onSaved,
  canonicalOnly = false,
}: {
  incidentId: string;
  actions: RemediationAction[];
  available: boolean;
  blockedReason?: string | null;
  onSaved: () => void;
  canonicalOnly?: boolean;
}) {
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<RemediationActionInput>(EMPTY);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!editingId) return;
    const action = actions.find((item) => item.remediation_action_id === editingId);
    if (!action) return;
    setForm({
      action_type: action.action_type,
      action_description: action.action_description,
      affected_component: action.affected_component,
      assigned_owner: action.assigned_owner,
      status: action.status,
      priority: action.priority,
      target_date: action.target_date,
      retest_required: action.retest_required,
      completion_notes: action.completion_notes,
    });
  }, [actions, editingId]);

  function update<K extends keyof RemediationActionInput>(
    key: K,
    value: RemediationActionInput[K],
  ) {
    setForm((previous) => ({ ...previous, [key]: value }));
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!available) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      if (editingId) {
        await api.updateRemediationAction(editingId, form);
        setMessage("Remediation action updated and recorded in the audit trail.");
      } else {
        await api.createRemediationAction(incidentId, form);
        setMessage("Remediation action recorded. Retest evidence is still required.");
      }
      setEditingId(null);
      setForm(EMPTY);
      onSaved();
    } catch {
      setError("The remediation action could not be saved. Use masked notes only.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div data-testid="remediation-action-panel" className="space-y-4">
      {actions.length ? (
        <div className="-mx-5 overflow-x-auto sm:-mx-6">
          <table className="data-table">
            <thead>
              <tr>
                <th>Action</th>
                <th>Component</th>
                <th>Owner</th>
                <th>Status</th>
                <th>Edit</th>
              </tr>
            </thead>
            <tbody>
              {actions.map((action) => (
                <tr key={action.remediation_action_id}>
                  <td>
                    <p className="font-medium text-navy-900">{sanitizeString(action.action_description)}</p>
                    <p className="mono-id">{action.remediation_action_id}</p>
                  </td>
                  <td>{sanitizeString(action.affected_component)}</td>
                  <td>{sanitizeString(action.assigned_owner)}</td>
                  <td><StatusBadge value={action.status} /></td>
                  <td>
                    <button
                      type="button"
                      onClick={() => setEditingId(action.remediation_action_id)}
                      className="text-sm font-medium text-accent hover:underline"
                    >
                      Edit
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-sm text-ink-muted">No remediation action has been recorded.</p>
      )}

      {!available ? (
        <p className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
          {blockedReason || "An approved human-review decision is required."}
        </p>
      ) : canonicalOnly && !editingId ? (
        <p className="text-sm text-ink-muted">
          {actions.length
            ? "The accepted diagnosis owns this action. Choose Edit to record progress."
            : "Accept the current diagnosis to create its single canonical remediation action."}
        </p>
      ) : (
        <form onSubmit={submit} className="space-y-3 rounded-md border border-slate-200 p-4">
          <div className="flex items-center justify-between gap-3">
            <h3 className="text-sm font-semibold text-navy-900">
              {editingId ? "Update remediation action" : "Record remediation action"}
            </h3>
            {editingId ? (
              <button
                type="button"
                onClick={() => { setEditingId(null); setForm(EMPTY); }}
                className="text-xs font-medium text-ink-muted hover:text-navy-900"
              >
                Add another
              </button>
            ) : null}
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <SelectField label="Action type" value={form.action_type} options={ACTION_TYPES} onChange={(value) => update("action_type", value)} />
            <SelectField label="Status" value={form.status} options={STATUSES} onChange={(value) => update("status", value)} />
            <InputField label="Affected component" value={form.affected_component} onChange={(value) => update("affected_component", value)} placeholder="payment logging middleware" />
            <InputField label="Assigned owner" value={form.assigned_owner} onChange={(value) => update("assigned_owner", value)} placeholder="payments platform team" />
            <SelectField label="Priority" value={form.priority} options={["low", "medium", "high", "critical"]} onChange={(value) => update("priority", value)} />
            <InputField label="Target date" value={form.target_date ?? ""} onChange={(value) => update("target_date", value || null)} type="date" />
          </div>
          <TextField label="Action description" value={form.action_description} onChange={(value) => update("action_description", value)} placeholder="Describe the human-owned change without raw evidence." required />
          <TextField label="Completion notes" value={form.completion_notes ?? ""} onChange={(value) => update("completion_notes", value || null)} placeholder="Required only when manually marking the action completed." />
          <label className="flex items-center gap-2 text-sm text-navy-900">
            <input type="checkbox" checked={form.retest_required} onChange={(event) => update("retest_required", event.target.checked)} />
            Retest evidence required
          </label>
          <button
            type="submit"
            disabled={busy || !form.action_description.trim() || !form.affected_component.trim() || !form.assigned_owner.trim() || (form.status === "completed" && !form.completion_notes?.trim())}
            className="btn-primary"
          >
            {busy ? "Saving..." : "Save remediation action"}
          </button>
        </form>
      )}
      {error ? <p className="text-sm text-red-700">{error}</p> : null}
      {message ? <p className="text-sm text-emerald-700">{message}</p> : null}
    </div>
  );
}

function InputField({ label, value, onChange, placeholder = "", type = "text" }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string; type?: string }) {
  return (
    <label className="text-sm font-medium text-ink-muted">
      {label}
      <input type={type} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} required={type !== "date"} className="field-control mt-1 block w-full" />
    </label>
  );
}

function SelectField({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) {
  return (
    <label className="text-sm font-medium text-ink-muted">
      {label}
      <select value={value} onChange={(event) => onChange(event.target.value)} className="field-control mt-1 block w-full">
        {options.map((option) => <option key={option} value={option}>{option.replaceAll("_", " ")}</option>)}
      </select>
    </label>
  );
}

function TextField({ label, value, onChange, placeholder, required = false }: { label: string; value: string; onChange: (value: string) => void; placeholder: string; required?: boolean }) {
  return (
    <label className="text-sm font-medium text-ink-muted">
      {label}
      <textarea rows={3} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} required={required} className="field-control mt-1 block w-full" />
    </label>
  );
}
