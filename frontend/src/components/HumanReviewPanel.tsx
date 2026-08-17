import { useEffect, useMemo, useState, type FormEvent } from "react";
import {
  api,
  type ReviewDecision,
  type ReviewDecisionValue,
  type RootCauseEvidenceStrength,
  type RootCauseScore,
} from "../api/client";
import { sanitizeString } from "../utils/safety";

interface DecisionOption {
  value: ReviewDecisionValue;
  label: string;
  resulting: string;
  hint: string;
}

const DECISIONS: DecisionOption[] = [
  {
    value: "approved",
    label: "Accept likely cause for remediation",
    resulting: "Remediation becomes available.",
    hint: "This does not verify a fix or close the incident.",
  },
  {
    value: "request_more_evidence",
    label: "Request more evidence",
    resulting: "Remediation remains blocked.",
    hint: "Name the missing evidence in the reason.",
  },
  {
    value: "rejected_false_positive",
    label: "Decline as false positive",
    resulting: "The incident is marked as a false-positive disposition.",
    hint: "The disposition remains in the audit record.",
  },
  {
    value: "escalated",
    label: "Escalate",
    resulting: "The incident remains under human review.",
    hint: "An escalation decision is still required.",
  },
];

export const HUMAN_REVIEW_CHECKLIST = [
  "Live alert reviewed, if applicable",
  "Masked detection reviewed",
  "Root-cause explanation reviewed",
  "Supporting evidence reviewed",
  "Contradicting evidence reviewed, if present",
  "Missing evidence reviewed",
  "Confidence limitation acknowledged",
];

function splitEvidenceIds(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export default function HumanReviewPanel({
  incidentId,
  topScore,
  rootStrength,
  detectionCount,
  missingEvidence,
  latestReview,
  onSubmitted,
}: {
  incidentId: string;
  topScore?: RootCauseScore | null;
  rootStrength?: RootCauseEvidenceStrength | null;
  detectionCount: number;
  missingEvidence: string[];
  latestReview?: ReviewDecision | null;
  onSubmitted?: () => void;
}) {
  const [decision, setDecision] = useState<ReviewDecisionValue>("approved");
  const [reason, setReason] = useState("");
  const [evidenceReliedOn, setEvidenceReliedOn] = useState("");
  const [evidenceLimitations, setEvidenceLimitations] = useState("");
  const [missingEvidenceNotes, setMissingEvidenceNotes] = useState("");
  const [checked, setChecked] = useState<boolean[]>(
    HUMAN_REVIEW_CHECKLIST.map(() => false),
  );
  const [busy, setBusy] = useState(false);
  const [draftBusy, setDraftBusy] = useState(false);
  const [draftLoaded, setDraftLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setDraftLoaded(false);
    api
      .getReviewDraft(incidentId)
      .then((draft) => {
        if (cancelled || !draft) return;
        setDecision(draft.selected_decision ?? "approved");
        setReason(draft.reason ?? "");
        setEvidenceReliedOn((draft.evidence_relied_on ?? []).join(", "));
        setEvidenceLimitations(draft.evidence_limitations ?? "");
        setMissingEvidenceNotes(draft.missing_evidence_notes ?? "");
        setChecked(
          HUMAN_REVIEW_CHECKLIST.map((item) =>
            (draft.evidence_checklist ?? []).includes(item),
          ),
        );
        setResult("Saved review draft restored.");
      })
      .catch(() => {
        if (!cancelled) setError("The saved review draft could not be loaded.");
      })
      .finally(() => {
        if (!cancelled) setDraftLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, [incidentId]);

  const selected = useMemo(
    () => DECISIONS.find((item) => item.value === decision) ?? DECISIONS[0],
    [decision],
  );
  const allChecked = checked.every(Boolean);
  const canSubmit = allChecked && reason.trim().length >= 10 && !busy && !draftBusy;
  const checklistValues = HUMAN_REVIEW_CHECKLIST.filter((_, index) => checked[index]);

  async function saveDraft() {
    setDraftBusy(true);
    setError(null);
    setResult(null);
    try {
      await api.saveReviewDraft(incidentId, {
        selected_decision: decision,
        reason: reason.trim() || null,
        evidence_checklist: checklistValues,
        evidence_relied_on: splitEvidenceIds(evidenceReliedOn),
        evidence_limitations: evidenceLimitations.trim() || null,
        missing_evidence_notes: missingEvidenceNotes.trim() || null,
        missing_evidence_acknowledged: checked[5],
      });
      setResult("Review draft saved. It does not unlock remediation.");
    } catch {
      setError("The review draft could not be saved. Use masked evidence only.");
    } finally {
      setDraftBusy(false);
    }
  }

  async function discardDraft() {
    setDraftBusy(true);
    setError(null);
    try {
      await api.deleteReviewDraft(incidentId);
      setResult("Saved review draft discarded.");
    } catch {
      setError("The saved review draft could not be discarded.");
    } finally {
      setDraftBusy(false);
    }
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      await api.submitReview(incidentId, {
        decision,
        reason: reason.trim(),
        evidence_checklist: checklistValues,
        evidence_relied_on: splitEvidenceIds(evidenceReliedOn),
        evidence_limitations: evidenceLimitations.trim() || undefined,
        missing_evidence_acknowledged: checked[5],
      });
      setResult(`Review recorded: ${selected.label}. ${selected.resulting}`);
      setReason("");
      setEvidenceReliedOn("");
      setEvidenceLimitations("");
      setMissingEvidenceNotes("");
      setChecked(HUMAN_REVIEW_CHECKLIST.map(() => false));
      onSubmitted?.();
    } catch {
      setError("The review could not be submitted. Use masked evidence and try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div data-testid="human-review-panel" className="space-y-4">
      <div className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
        <Summary
          label="Likely cause"
          value={rootStrength?.likely_root_cause ?? topScore?.likely_root_cause ?? "Not analysed"}
        />
        <Summary
          label="Confidence level"
          value={rootStrength?.confidence_level ?? topScore?.confidence_band ?? "Not available"}
        />
        <Summary label="Masked detections" value={String(detectionCount)} />
        <Summary
          label="Missing evidence"
          value={missingEvidence.length ? missingEvidence.slice(0, 3).join(", ") : "None listed"}
        />
      </div>

      {latestReview ? (
        <p className="rounded-md border border-slate-200 bg-slate-50 p-2 text-xs text-slate-600">
          Latest final decision: {sanitizeString(latestReview.decision)} at {latestReview.timestamp}.
        </p>
      ) : (
        <p className="rounded-md border border-amber-200 bg-amber-50 p-2 text-xs text-amber-900">
          Human review has not been completed.
        </p>
      )}

      <form onSubmit={onSubmit} className="space-y-4">
        <fieldset>
          <legend className="text-xs font-medium uppercase text-slate-500">
            Evidence reviewed
          </legend>
          <div className="mt-2 grid gap-2 sm:grid-cols-2">
            {HUMAN_REVIEW_CHECKLIST.map((item, index) => (
              <label key={item} className="flex items-start gap-2 text-sm text-slate-700">
                <input
                  type="checkbox"
                  checked={checked[index]}
                  onChange={(event) =>
                    setChecked((previous) =>
                      previous.map((value, itemIndex) =>
                        itemIndex === index ? event.target.checked : value,
                      ),
                    )
                  }
                />
                {item}
              </label>
            ))}
          </div>
        </fieldset>

        <div>
          <label htmlFor="review-decision" className="text-xs font-medium uppercase text-slate-500">
            Decision
          </label>
          <select
            id="review-decision"
            value={decision}
            onChange={(event) => setDecision(event.target.value as ReviewDecisionValue)}
            className="mt-1 block w-full max-w-md rounded-md border border-slate-300 px-2 py-1.5 text-sm"
          >
            {DECISIONS.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
          <p data-testid="resulting-status" className="mt-1 text-xs text-slate-600">
            {selected.resulting} {selected.hint}
          </p>
        </div>

        <TextArea
          id="review-reason"
          label="Decision reason (required)"
          value={reason}
          onChange={setReason}
          placeholder="Explain the decision using masked evidence only."
          required
        />
        <div className="grid gap-3 sm:grid-cols-2">
          <TextArea
            id="review-evidence"
            label="Evidence relied on (IDs)"
            value={evidenceReliedOn}
            onChange={setEvidenceReliedOn}
            placeholder="EVD-001, ALERT-001"
          />
          <TextArea
            id="review-limitations"
            label="Evidence limitations"
            value={evidenceLimitations}
            onChange={setEvidenceLimitations}
            placeholder="State confidence and evidence limitations."
          />
        </div>
        <TextArea
          id="review-missing-notes"
          label="Missing evidence notes"
          value={missingEvidenceNotes}
          onChange={setMissingEvidenceNotes}
          placeholder="Note evidence that should be collected next."
        />

        <div className="flex flex-wrap gap-2">
          <button
            type="submit"
            disabled={!canSubmit}
            className="rounded-md bg-navy-700 px-4 py-2 text-sm font-medium text-white hover:bg-navy-800 disabled:cursor-not-allowed disabled:bg-slate-300"
          >
            {busy ? "Submitting..." : "Submit decision"}
          </button>
          <button
            type="button"
            disabled={draftBusy || !draftLoaded}
            onClick={saveDraft}
            className="rounded-md border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 disabled:opacity-50"
          >
            {draftBusy ? "Saving..." : "Save draft"}
          </button>
          <button
            type="button"
            disabled={draftBusy || !draftLoaded}
            onClick={discardDraft}
            className="text-sm font-medium text-slate-600 hover:text-slate-900 disabled:opacity-50"
          >
            Discard draft
          </button>
        </div>
        {!allChecked ? (
          <p className="text-xs text-slate-500">Complete the review checklist to submit.</p>
        ) : null}
        {reason.trim().length > 0 && reason.trim().length < 10 ? (
          <p className="text-xs text-amber-700">Use at least 10 characters for the reason.</p>
        ) : null}
        {error ? <p className="text-sm text-red-700">{error}</p> : null}
        {result ? (
          <p className="rounded-md border border-emerald-200 bg-emerald-50 p-2 text-sm text-emerald-900">
            {result}
          </p>
        ) : null}
      </form>
    </div>
  );
}

function Summary({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs text-slate-500">{label}</p>
      <p>{sanitizeString(value)}</p>
    </div>
  );
}

function TextArea({
  id,
  label,
  value,
  onChange,
  placeholder,
  required = false,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  required?: boolean;
}) {
  return (
    <div>
      <label htmlFor={id} className="text-xs font-medium text-slate-500">
        {label}
      </label>
      <textarea
        id={id}
        rows={3}
        value={value}
        required={required}
        minLength={required ? 10 : undefined}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="mt-1 block w-full rounded-md border border-slate-300 px-2 py-1.5 text-sm"
      />
    </div>
  );
}
