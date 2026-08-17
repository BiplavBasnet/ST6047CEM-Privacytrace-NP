import { useState, type FormEvent } from "react";
import {
  aiRemediationApi,
  type AIRemediationDecisionResponse,
  type AIRemediationSuggestion,
} from "../api/aiRemediationClient";
import { findUnsafeAIRemediationText } from "../utils/aiRemediationSafety";
import { sanitizeString } from "../utils/safety";

type DecisionAction = "accept" | "edit" | "reject";

const REVIEW_BLOCK_MESSAGE =
  "Reviewer input was blocked because it contains raw sensitive content or unsafe claims.";

function splitActions(value: string): string[] {
  return value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

export default function AISuggestionDecisionPanel({
  suggestion,
  canReview,
  onDecision,
}: {
  suggestion: AIRemediationSuggestion | null;
  canReview: boolean;
  onDecision: () => void;
}) {
  const [acceptNotes, setAcceptNotes] = useState("");
  const [createAction, setCreateAction] = useState(true);
  const [editActions, setEditActions] = useState("");
  const [editNotes, setEditNotes] = useState("");
  const [rejectReason, setRejectReason] = useState("");
  const [busy, setBusy] = useState<DecisionAction | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);

  if (!suggestion) return null;
  const currentSuggestion = suggestion;
  if (!canReview) {
    return (
      <p className="rounded-md border border-slate-200 bg-slate-50 p-2 text-sm text-slate-600">
        Your role can read AI remediation suggestions but cannot accept, edit, or reject them.
      </p>
    );
  }

  function ensureSafe(value: unknown): boolean {
    const violations = findUnsafeAIRemediationText(value);
    if (violations.length) {
      setError(REVIEW_BLOCK_MESSAGE);
      setResult(null);
      return false;
    }
    return true;
  }

  async function runDecision(action: DecisionAction, work: () => Promise<AIRemediationDecisionResponse>) {
    setBusy(action);
    setError(null);
    setResult(null);
    try {
      const response = await work();
      setResult(response.message);
      setAcceptNotes("");
      setEditActions("");
      setEditNotes("");
      setRejectReason("");
      onDecision();
    } catch (err) {
      setError(
        err instanceof Error
          ? sanitizeString(err.message)
          : "AI remediation decision could not be recorded.",
      );
    } finally {
      setBusy(null);
    }
  }

  function onAccept(event: FormEvent) {
    event.preventDefault();
    if (!ensureSafe(acceptNotes)) return;
    void runDecision("accept", () =>
      aiRemediationApi.accept(currentSuggestion.suggestion_id, acceptNotes, createAction),
    );
  }

  function onEdit(event: FormEvent) {
    event.preventDefault();
    const actions = splitActions(editActions);
    if (!actions.length) {
      setError("Add at least one reviewer-edited remediation action.");
      return;
    }
    if (!ensureSafe({ actions, editNotes })) return;
    void runDecision("edit", () =>
      aiRemediationApi.edit(currentSuggestion.suggestion_id, actions, editNotes),
    );
  }

  function onReject(event: FormEvent) {
    event.preventDefault();
    if (!rejectReason.trim()) {
      setError("Add a rejection reason.");
      return;
    }
    if (!ensureSafe(rejectReason)) return;
    void runDecision("reject", () =>
      aiRemediationApi.reject(currentSuggestion.suggestion_id, rejectReason),
    );
  }

  const acceptedDisabled = busy !== null || currentSuggestion.status === "rejected_by_reviewer";

  return (
    <div data-testid="ai-suggestion-decision-panel" className="space-y-4">
      <div className="rounded-md border border-slate-200 bg-slate-50 p-2 text-xs text-slate-600">
        Reviewer actions update the AI suggestion record only. They do not verify the fix or close the incident.
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <form onSubmit={onAccept} className="space-y-2 rounded-md border border-slate-200 p-3">
          <h4 className="text-sm font-semibold text-slate-800">Accept suggestion</h4>
          <textarea
            aria-label="Acceptance notes"
            value={acceptNotes}
            onChange={(event) => setAcceptNotes(event.target.value)}
            rows={4}
            placeholder="Reviewer notes using masked evidence only"
            className="block w-full rounded-md border border-slate-300 px-2 py-1.5 text-sm"
          />
          <label className="flex items-center gap-2 text-sm text-slate-600">
            <input
              type="checkbox"
              checked={createAction}
              onChange={(event) => setCreateAction(event.target.checked)}
            />
            Create remediation action reference
          </label>
          <button
            type="submit"
            disabled={acceptedDisabled}
            className="rounded-lg bg-navy-700 px-3 py-1.5 text-xs font-medium text-white disabled:bg-slate-300 disabled:text-slate-500"
          >
            {busy === "accept" ? "Accepting..." : "Accept suggestion"}
          </button>
        </form>

        <form onSubmit={onEdit} className="space-y-2 rounded-md border border-slate-200 p-3">
          <h4 className="text-sm font-semibold text-slate-800">Edit actions</h4>
          <textarea
            aria-label="Edited remediation actions"
            value={editActions}
            onChange={(event) => setEditActions(event.target.value)}
            rows={4}
            placeholder="One remediation action per line"
            className="block w-full rounded-md border border-slate-300 px-2 py-1.5 text-sm"
          />
          <input
            aria-label="Edit notes"
            value={editNotes}
            onChange={(event) => setEditNotes(event.target.value)}
            placeholder="Reviewer edit notes"
            className="block w-full rounded-md border border-slate-300 px-2 py-1.5 text-sm"
          />
          <button
            type="submit"
            disabled={busy !== null}
            className="rounded-md border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 disabled:text-slate-400"
          >
            {busy === "edit" ? "Saving..." : "Save reviewer edit"}
          </button>
        </form>

        <form onSubmit={onReject} className="space-y-2 rounded-md border border-slate-200 p-3">
          <h4 className="text-sm font-semibold text-slate-800">Reject suggestion</h4>
          <textarea
            aria-label="Rejection reason"
            value={rejectReason}
            onChange={(event) => setRejectReason(event.target.value)}
            rows={4}
            placeholder="Reason for rejection"
            className="block w-full rounded-md border border-slate-300 px-2 py-1.5 text-sm"
          />
          <button
            type="submit"
            disabled={busy !== null}
            className="rounded-md border border-red-200 px-3 py-1.5 text-xs font-medium text-red-700 disabled:text-slate-400"
          >
            {busy === "reject" ? "Rejecting..." : "Reject suggestion"}
          </button>
        </form>
      </div>

      {error ? <p className="text-sm text-red-700">{sanitizeString(error)}</p> : null}
      {result ? (
        <p className="rounded-md border border-emerald-200 bg-emerald-50 p-2 text-sm text-emerald-900">
          {sanitizeString(result)}
        </p>
      ) : null}
    </div>
  );
}
