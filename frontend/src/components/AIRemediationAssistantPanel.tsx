import { useCallback, useEffect, useMemo, useState } from "react";
import {
  aiRemediationApi,
  type AIRemediationStatus,
  type AIRemediationSuggestion,
} from "../api/aiRemediationClient";
import { useAuth } from "../context/AuthContext";
import { sanitizeString } from "../utils/safety";
import AISafetyNotice from "./AISafetyNotice";
import AISuggestionCard from "./AISuggestionCard";
import AISuggestionDecisionPanel from "./AISuggestionDecisionPanel";
import { ErrorState, LoadingState } from "./LoadingError";
import SafeErrorMessage from "./SafeErrorMessage";
import StatusBadge from "./StatusBadge";

export default function AIRemediationAssistantPanel({ incidentId }: { incidentId: string }) {
  const { can } = useAuth();
  const canRead = can("ai_remediation:read");
  const canGenerate = can("ai_remediation:generate");
  const canReview = can("ai_remediation:review");

  const [status, setStatus] = useState<AIRemediationStatus | null>(null);
  const [suggestions, setSuggestions] = useState<AIRemediationSuggestion[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const selected = useMemo(
    () => suggestions.find((item) => item.suggestion_id === selectedId) ?? suggestions[0] ?? null,
    [selectedId, suggestions],
  );

  const load = useCallback(async () => {
    if (!canRead) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const [statusData, suggestionData] = await Promise.all([
        aiRemediationApi.getStatus(),
        aiRemediationApi.listByIncident(incidentId),
      ]);
      setStatus(statusData);
      setSuggestions(suggestionData.suggestions);
      setSelectedId((current) =>
        current && suggestionData.suggestions.some((item) => item.suggestion_id === current)
          ? current
          : suggestionData.suggestions[0]?.suggestion_id ?? null,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "AI remediation data could not be loaded.");
    } finally {
      setLoading(false);
    }
  }, [canRead, incidentId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function onGenerate() {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const response = await aiRemediationApi.suggest(incidentId);
      setNotice(response.message);
      setSuggestions((current) => [
        response.suggestion,
        ...current.filter((item) => item.suggestion_id !== response.suggestion.suggestion_id),
      ]);
      setSelectedId(response.suggestion.suggestion_id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "AI remediation suggestion could not be generated.");
    } finally {
      setBusy(false);
    }
  }

  if (!canRead) {
    return (
      <SafeErrorMessage
        title="AI Remediation Assistant is restricted"
        message="Your role cannot view AI remediation suggestions."
        hint="Required permission: ai_remediation:read"
      />
    );
  }

  const providerReady = !!status?.enabled && !!status?.provider_configured;
  const generateDisabled = busy || !providerReady || !canGenerate;

  return (
    <div data-testid="ai-remediation-panel" className="space-y-4">
      <AISafetyNotice />

      {loading ? <LoadingState message="Loading AI remediation assistant..." /> : null}
      {error ? <ErrorState message={sanitizeString(error)} /> : null}

      <div className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
          <p className="text-xs text-slate-500">Assistant</p>
          <p className="mt-1">
            <StatusBadge value={status?.enabled ? "enabled" : "disabled"} />
          </p>
        </div>
        <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
          <p className="text-xs text-slate-500">Provider</p>
          <p className="mt-1">
            <StatusBadge value={status?.provider_configured ? "configured" : "not_configured"} />
          </p>
        </div>
        <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
          <p className="text-xs text-slate-500">Model</p>
          <p className="mt-1 break-words">{sanitizeString(status?.model ?? "not configured")}</p>
        </div>
        <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
          <p className="text-xs text-slate-500">Suggestions</p>
          <p className="mt-1 font-medium text-slate-900">{suggestions.length}</p>
        </div>
      </div>

      {status?.message ? (
        <p className="rounded-md border border-slate-200 bg-white p-2 text-sm text-slate-700">
          {sanitizeString(status.message)}
        </p>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        {canGenerate ? (
          <button
            type="button"
            onClick={onGenerate}
            disabled={generateDisabled}
            className="rounded-lg bg-navy-700 px-4 py-2 text-sm font-medium text-white hover:bg-navy-800 disabled:cursor-not-allowed disabled:bg-slate-300 disabled:text-slate-500"
          >
            {busy ? "Generating..." : "Generate AI suggestion"}
          </button>
        ) : (
          <p className="text-sm text-slate-600">
            Your role can read suggestions but cannot generate new AI remediation guidance.
          </p>
        )}
        {canGenerate && !providerReady ? (
          <p className="text-xs text-amber-700">
            Generation is unavailable until the assistant is enabled and the provider is configured.
          </p>
        ) : null}
      </div>

      {notice ? (
        <p className="rounded-md border border-emerald-200 bg-emerald-50 p-2 text-sm text-emerald-900">
          {sanitizeString(notice)}
        </p>
      ) : null}

      {suggestions.length > 1 ? (
        <div>
          <label htmlFor="ai-suggestion-select" className="text-xs text-slate-500">
            Suggestion history
          </label>
          <select
            id="ai-suggestion-select"
            value={selected?.suggestion_id ?? ""}
            onChange={(event) => setSelectedId(event.target.value)}
            className="mt-1 block w-full max-w-md rounded-md border border-slate-300 px-2 py-1.5 text-sm"
          >
            {suggestions.map((suggestion) => (
              <option key={suggestion.suggestion_id} value={suggestion.suggestion_id}>
                {suggestion.suggestion_id} - {suggestion.status}
              </option>
            ))}
          </select>
        </div>
      ) : null}

      <AISuggestionCard suggestion={selected} />
      <AISuggestionDecisionPanel
        suggestion={selected}
        canReview={canReview}
        onDecision={() => void load()}
      />
    </div>
  );
}
