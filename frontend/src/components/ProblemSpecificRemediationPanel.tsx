import { useEffect, useState } from "react";
import {
  aiRemediationApi,
  type CurrentRemediationDiagnosis,
  type ProblemSpecificRemediationResponse,
} from "../api/aiRemediationClient";
import { useAuth } from "../context/AuthContext";
import CollapsibleSection from "./CollapsibleSection";
import SafeErrorMessage from "./SafeErrorMessage";

/**
 * Evidence-grounded primary remediation UI.
 * Shows one best-supported remediation; alternatives only when API returns them.
 */
export default function ProblemSpecificRemediationPanel({
  incidentId,
  currentDiagnosisId,
  currentGenerationMode,
  chainStatus,
  onChanged,
  currentDiagnosis,
}: {
  incidentId: string;
  currentDiagnosisId?: string | null;
  currentGenerationMode?: string | null;
  chainStatus?: string;
  onChanged?: () => void;
  currentDiagnosis?: CurrentRemediationDiagnosis | null;
}) {
  const { can } = useAuth();
  const canGenerate = can("ai_remediation:generate");
  const canReview = can("ai_remediation:review");

  const [data, setData] = useState<ProblemSpecificRemediationResponse | null>(null);
  const [diagnosisId, setDiagnosisId] = useState<string | null>(null);
  const [notes, setNotes] = useState("");
  const [editedChange, setEditedChange] = useState("");
  const [editedTitle, setEditedTitle] = useState("");
  const [editedProblem, setEditedProblem] = useState("");
  const [editedComponent, setEditedComponent] = useState("");
  const [editedTests, setEditedTests] = useState("");
  const [editedRetest, setEditedRetest] = useState("");
  const [editedRollback, setEditedRollback] = useState("");
  const [editedRisk, setEditedRisk] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    if (!currentDiagnosis || data) return;
    const primary = currentDiagnosis.primary_remediation;
    setDiagnosisId(currentDiagnosis.diagnosis_id);
    setEditedChange(primary.recommended_change);
    setEditedTitle(primary.title);
    setEditedProblem(currentDiagnosis.problem_statement);
    setEditedComponent(primary.affected_component);
    setEditedTests((primary.tests_required || []).join("\n"));
    setEditedRetest((primary.retest_requirements || []).join("\n"));
    setEditedRollback(primary.rollback_plan);
    setEditedRisk(primary.implementation_risk);
  }, [currentDiagnosis, data]);

  async function onDiagnose() {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const response = await aiRemediationApi.diagnose(incidentId);
      setData(response);
      setDiagnosisId(response.diagnosis_id);
      setEditedChange(response.primary_remediation.recommended_change);
      setEditedTitle(response.primary_remediation.title);
      setEditedProblem(response.diagnosis.problem_statement);
      setEditedComponent(response.primary_remediation.affected_component);
      setEditedTests((response.primary_remediation.tests_required || []).join("\n"));
      setEditedRetest((response.primary_remediation.retest_requirements || []).join("\n"));
      setEditedRollback(response.primary_remediation.rollback_plan);
      setEditedRisk(response.primary_remediation.implementation_risk);
      setNotice("Primary best-supported remediation generated. Human approval required.");
      onChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Diagnosis failed.");
    } finally {
      setBusy(false);
    }
  }

  async function onReview(decision: string, createAction: boolean) {
    const persistedPrimary = data?.primary_remediation ?? currentDiagnosis?.primary_remediation;
    if (!diagnosisId || !persistedPrimary) {
      setError("Load or generate a primary remediation before human review.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const editedPrimary =
        decision === "accept_with_edits"
          ? {
              ...persistedPrimary,
              title: editedTitle.trim() || persistedPrimary.title,
              recommended_change: editedChange.trim(),
              affected_component: editedComponent.trim() || persistedPrimary.affected_component,
              implementation_risk: editedRisk.trim() || persistedPrimary.implementation_risk,
              rollback_plan: editedRollback.trim() || persistedPrimary.rollback_plan,
              tests_required: editedTests
                .split("\n")
                .map((line) => line.trim())
                .filter(Boolean),
              retest_requirements: editedRetest
                .split("\n")
                .map((line) => line.trim())
                .filter(Boolean),
              problem_statement: editedProblem.trim() || data?.diagnosis.problem_statement || currentDiagnosis?.problem_statement,
            }
          : null;
      if (decision === "accept_with_edits" && !editedChange.trim()) {
        setError("Edit and Accept requires an edited recommended change.");
        setBusy(false);
        return;
      }
      const result = await aiRemediationApi.reviewDiagnosis(
        diagnosisId,
        decision,
        notes,
        createAction,
        editedPrimary,
      );
      setNotice(result.message);
      onChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Review failed.");
    } finally {
      setBusy(false);
    }
  }

  const primary = data?.primary_remediation ?? currentDiagnosis?.primary_remediation;
  const diagnosis = data?.diagnosis ?? (currentDiagnosis ? {
    problem_statement: currentDiagnosis.problem_statement,
    technical_mechanism: currentDiagnosis.technical_mechanism,
    exact_source_location_known: currentDiagnosis.exact_source_location_known,
    affected_component: currentDiagnosis.affected_component,
    affected_file_if_known: currentDiagnosis.affected_file,
    affected_function_if_known: currentDiagnosis.affected_function,
    missing_evidence: currentDiagnosis.missing_evidence,
  } : null);

  return (
    <div data-testid="problem-specific-remediation-panel" className="space-y-4">
      <p className="text-sm text-ink-muted">
        Evidence-grounded remediation proposes one best-supported change from masked evidence.
        Human approval is required before any Remediation Action or controlled sandbox patch.
      </p>
      {currentDiagnosisId && !currentDiagnosis && !data ? (
        <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-sm" role="status">
          <p className="font-medium text-navy-900">Current diagnosis: {currentDiagnosisId}</p>
          <p className="mt-1 text-ink-muted">
            Generation mode: {modeLabel(currentGenerationMode)}. Chain: {chainStatus ?? "blocked"}.
            Detailed diagnosis text is available after generation in this session; workflow status remains authoritative after reload.
          </p>
        </div>
      ) : null}
      {canGenerate && !currentDiagnosis ? (
        <button
          type="button"
          className="btn btn-primary"
          disabled={busy}
          onClick={() => void onDiagnose()}
        >
          Generate primary remediation
        </button>
      ) : null}
      {error ? <SafeErrorMessage title="Remediation error" message={error} /> : null}
      {notice ? <p className="text-sm text-ink">{notice}</p> : null}

      {diagnosis && primary ? (
        <div className="space-y-3 rounded border border-edge bg-surface p-4">
          <section>
            <p className="mb-3 text-xs font-medium text-ink-muted" role="status">
              Generation mode: {modeLabel(data?.generation_mode ?? currentDiagnosis?.generation_mode)}
              {data?.generation_mode === "fallback_playbook" ? ` — AI enrichment failed (${data.ai_failure_type ?? "unavailable"}); verified playbook output is shown.` : ""}
            </p>
            <h3 className="text-sm font-semibold uppercase tracking-wide text-ink-subtle">
              Exact problem
            </h3>
            <p className="mt-1 text-sm">{diagnosis.problem_statement}</p>
            {diagnosis.technical_mechanism ? <p className="mt-1 text-xs text-ink-muted">{diagnosis.technical_mechanism}</p> : null}
          </section>

          <section>
            <h3 className="text-sm font-semibold uppercase tracking-wide text-ink-subtle">
              Relevant code/config evidence
            </h3>
            {diagnosis.exact_source_location_known === true ? (
              <ul className="mt-1 list-disc pl-5 text-sm">
                <li>Affected file: {diagnosis.affected_file_if_known}</li>
                {diagnosis.affected_function_if_known ? (
                  <li>Affected function: {diagnosis.affected_function_if_known}</li>
                ) : null}
              </ul>
            ) : diagnosis.exact_source_location_known === false ? (
              <div className="mt-1 text-sm">
                <p>Affected component: {diagnosis.affected_component ?? "Not established"}</p>
                <p>Exact source location: Not established</p>
                <p className="text-ink-muted">
                  Next evidence required:{" "}
                  {diagnosis.missing_evidence?.[0] ??
                    "Repository mapping or source-level scanner evidence."}
                </p>
              </div>
            ) : null}
          </section>

          <section className="rounded bg-canvas p-3">
            <h3 className="text-base font-semibold">PRIMARY REMEDIATION</h3>
            <p className="mt-1 font-medium">{primary.title}</p>
            <p className="mt-2 text-sm">
              <span className="font-medium">Recommended change:</span> {primary.recommended_change}
            </p>
            <p className="mt-2 text-sm">
              <span className="font-medium">Why this remediation:</span> {primary.why_this_solution}
            </p>
            <p className="mt-2 text-sm text-ink-muted">{primary.why_not_broader_fix}</p>
            <p className="mt-2 text-xs">
              Confidence: {primary.remediation_confidence} · Risk: {primary.implementation_risk}
            </p>
          </section>

          {data?.alternative_remediations?.length ? (
            <CollapsibleSection summary="Alternative remediations (ambiguity only)">
              <ul className="list-disc space-y-2 pl-5 text-sm">
                {data.alternative_remediations.map((alt) => (
                  <li key={alt.remediation_id}>
                    <strong>{alt.title}</strong> — {alt.recommended_change}
                  </li>
                ))}
              </ul>
            </CollapsibleSection>
          ) : null}

          <CollapsibleSection summary="Risks, tests, retest, rollback">
            <ul className="list-disc space-y-1 pl-5 text-sm">
              <li>Privacy impact: {primary.expected_privacy_impact}</li>
              <li>Operational impact: {primary.operational_impact}</li>
              {primary.tests_required.map((item) => (
                <li key={item}>Test: {item}</li>
              ))}
              {primary.retest_requirements.map((item) => (
                <li key={item}>Retest: {item}</li>
              ))}
              <li>Rollback: {primary.rollback_plan}</li>
            </ul>
          </CollapsibleSection>

          {data?.exact_change_available && data.proposed_change ? (
            <CollapsibleSection summary="Proposed code/config change">
              <p className="text-sm">File: {data.proposed_change.file_path}</p>
              <pre className="mt-2 overflow-auto rounded bg-canvas p-2 text-xs">
                {data.proposed_change.proposed_diff}
              </pre>
            </CollapsibleSection>
          ) : (
            <p className="text-xs text-ink-muted">
              Exact change available: false — component-level remediation only until source evidence
              is established.
            </p>
          )}

          {canReview ? (
            <div className="space-y-2 border-t border-edge pt-3">
              <label className="block text-sm">
                Edit problem statement
                <textarea
                  className="mt-1 w-full rounded border border-edge bg-canvas p-2 text-sm"
                  rows={2}
                  value={editedProblem}
                  onChange={(e) => setEditedProblem(e.target.value)}
                />
              </label>
              <label className="block text-sm">
                Edit remediation title
                <input
                  className="mt-1 w-full rounded border border-edge bg-canvas p-2 text-sm"
                  value={editedTitle}
                  onChange={(e) => setEditedTitle(e.target.value)}
                />
              </label>
              <label className="block text-sm">
                Edit recommended change
                <textarea
                  className="mt-1 w-full rounded border border-edge bg-canvas p-2 text-sm"
                  rows={3}
                  value={editedChange}
                  onChange={(e) => setEditedChange(e.target.value)}
                />
              </label>
              <label className="block text-sm">
                Edit affected component
                <input
                  className="mt-1 w-full rounded border border-edge bg-canvas p-2 text-sm"
                  value={editedComponent}
                  onChange={(e) => setEditedComponent(e.target.value)}
                />
              </label>
              <label className="block text-sm">
                Edit required tests (one per line)
                <textarea
                  className="mt-1 w-full rounded border border-edge bg-canvas p-2 text-sm"
                  rows={2}
                  value={editedTests}
                  onChange={(e) => setEditedTests(e.target.value)}
                />
              </label>
              <label className="block text-sm">
                Edit retest requirements (one per line)
                <textarea
                  className="mt-1 w-full rounded border border-edge bg-canvas p-2 text-sm"
                  rows={2}
                  value={editedRetest}
                  onChange={(e) => setEditedRetest(e.target.value)}
                />
              </label>
              <label className="block text-sm">
                Edit risk / rollback
                <textarea
                  className="mt-1 w-full rounded border border-edge bg-canvas p-2 text-sm"
                  rows={2}
                  value={editedRisk}
                  onChange={(e) => setEditedRisk(e.target.value)}
                />
                <textarea
                  className="mt-1 w-full rounded border border-edge bg-canvas p-2 text-sm"
                  rows={2}
                  value={editedRollback}
                  onChange={(e) => setEditedRollback(e.target.value)}
                />
              </label>
              <label className="block text-sm">
                Review notes / rejection reason
                <textarea
                  className="mt-1 w-full rounded border border-edge bg-canvas p-2 text-sm"
                  rows={3}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                />
              </label>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={busy}
                  onClick={() => void onReview("accept", true)}
                >
                  Accept
                </button>
                <button
                  type="button"
                  className="btn"
                  disabled={busy}
                  onClick={() => void onReview("accept_with_edits", true)}
                >
                  Edit and Accept
                </button>
                <button
                  type="button"
                  className="btn"
                  disabled={busy}
                  onClick={() => void onReview("reject", false)}
                >
                  Reject
                </button>
                <button
                  type="button"
                  className="btn"
                  disabled={busy}
                  onClick={() => void onReview("request_more_evidence", false)}
                >
                  Request More Evidence
                </button>
              </div>
              <p className="text-xs text-ink-subtle">
                AI cannot approve its own remediation. Rejected / more-evidence states do not unlock
                controlled patch execution.
              </p>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function modeLabel(mode?: string | null) {
  if (mode === "playbook_plus_ai") return "Playbook + AI";
  if (mode === "fallback_playbook") return "Fallback";
  return "Playbook";
}
