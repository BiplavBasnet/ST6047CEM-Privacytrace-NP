import type { ReactNode } from "react";
import type { LlmReportSummary, RootCauseScore } from "../../api/client";
import Card from "../Card";
import { sanitizeString } from "../../utils/safety";

export default function WhyThisCausePanel({
  topCause,
  explanation,
}: {
  topCause: RootCauseScore | undefined;
  explanation: LlmReportSummary | undefined;
}) {
  if (!topCause) {
    return (
      <Card title="Why this likely cause">
        <p className="text-sm text-slate-600">No ranked likely cause available yet.</p>
      </Card>
    );
  }

  const confidenceLabel =
    topCause.confidence_band ??
    (topCause.confidence != null ? String(topCause.confidence) : "—");

  const supportingIds = topCause.supporting_evidence_ids ?? [];
  const missing = topCause.missing_evidence ?? [];

  return (
    <Card title="Why this likely cause">
      <dl className="space-y-2 text-sm">
        <Row label="Likely cause">{sanitizeString(topCause.likely_root_cause)}</Row>
        <Row label="Confidence level">{sanitizeString(confidenceLabel)}</Row>
        <Row label="Supporting evidence IDs">
          {supportingIds.length ? supportingIds.join(", ") : "none listed"}
        </Row>
        <Row label="Missing evidence">
          {missing.length ? missing.map((m) => sanitizeString(m)).join(", ") : "none listed"}
        </Row>
        <Row label="Recommended fix">
          {sanitizeString(topCause.recommended_fix ?? "—")}
        </Row>
        <Row label="Safe explanation">
          {sanitizeString(
            explanation?.top_likely_cause_preview ??
              explanation?.incident_summary_preview ??
              "Guarded explanation not generated yet. Human review required before closure.",
          )}
        </Row>
      </dl>
      <p className="mt-3 text-xs text-slate-500">
        Wording uses likely cause, supporting evidence, and confidence level only. Human
        review is required before closure.
      </p>
    </Card>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className="text-slate-800">{children}</dd>
    </div>
  );
}
