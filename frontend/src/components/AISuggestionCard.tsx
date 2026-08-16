import type { AIRemediationSuggestion } from "../api/aiRemediationClient";
import { sanitizeString } from "../utils/safety";
import StatusBadge from "./StatusBadge";

function DetailList({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <h4 className="text-xs font-medium uppercase tracking-wide text-slate-500">{title}</h4>
      {items.length ? (
        <ul className="mt-2 list-inside list-disc space-y-1 text-sm text-slate-700">
          {items.map((item, index) => (
            <li key={`${title}-${index}`}>{sanitizeString(item)}</li>
          ))}
        </ul>
      ) : (
        <p className="mt-2 text-sm text-slate-500">None listed.</p>
      )}
    </div>
  );
}

export default function AISuggestionCard({
  suggestion,
}: {
  suggestion: AIRemediationSuggestion | null;
}) {
  if (!suggestion) {
    return (
      <p className="text-sm text-slate-600">
        No AI remediation suggestions have been generated for this incident.
      </p>
    );
  }

  return (
    <article data-testid="ai-suggestion-card" className="space-y-4 text-sm text-slate-700">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-mono text-xs text-slate-500">
            {sanitizeString(suggestion.suggestion_id)}
          </p>
          <h3 className="text-base font-semibold text-slate-900">
            {sanitizeString(suggestion.suggestion_summary ?? "AI remediation suggestion")}
          </h3>
        </div>
        <div className="flex flex-wrap gap-2">
          <StatusBadge value={suggestion.status} />
          <StatusBadge value={suggestion.output_safety_status} />
        </div>
      </div>

      <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <dt className="text-xs text-slate-500">Issue area</dt>
          <dd>{sanitizeString(suggestion.likely_issue_area ?? "not specified")}</dd>
        </div>
        <div>
          <dt className="text-xs text-slate-500">Provider</dt>
          <dd>{sanitizeString(suggestion.ai_provider ?? "not recorded")}</dd>
        </div>
        <div>
          <dt className="text-xs text-slate-500">Model</dt>
          <dd>{sanitizeString(suggestion.ai_model ?? "not recorded")}</dd>
        </div>
        <div>
          <dt className="text-xs text-slate-500">Input safety</dt>
          <dd>{sanitizeString(suggestion.input_safety_status)}</dd>
        </div>
      </dl>

      <div className="grid gap-4 lg:grid-cols-2">
        <DetailList title="Remediation actions" items={suggestion.remediation_actions} />
        <DetailList title="Code or config areas" items={suggestion.code_or_config_areas} />
        <DetailList title="Suggested tests" items={suggestion.suggested_tests} />
        <DetailList title="Retest evidence required" items={suggestion.retest_evidence_required} />
      </div>

      <DetailList title="Limitations" items={suggestion.limitations} />

      <div className="rounded-md border border-slate-200 bg-slate-50 p-2 text-xs text-slate-600">
        <p>Masked input hash: {sanitizeString(suggestion.masked_input_summary_hash)}</p>
        <p>
          Human review required: {suggestion.human_review_required ? "yes" : "no"}
          {suggestion.reviewer_decision
            ? ` | Reviewer decision: ${sanitizeString(suggestion.reviewer_decision)}`
            : ""}
        </p>
        {suggestion.accepted_as_remediation_action_id ? (
          <p>
            Remediation action reference: {sanitizeString(suggestion.accepted_as_remediation_action_id)}
          </p>
        ) : null}
      </div>
    </article>
  );
}
