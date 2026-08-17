import type { FixVerification, IncidentDetail } from "../../api/client";
import Card from "../Card";
import StatusBadge from "../StatusBadge";
import { sanitizeString } from "../../utils/safety";

export default function FixVerificationComparisonPanel({
  incident,
  detections,
  verification,
  humanReviewRequired,
}: {
  incident: IncidentDetail;
  detections: Record<string, unknown>[];
  verification: FixVerification | undefined;
  humanReviewRequired: boolean;
}) {
  const sensitiveTypes = [
    ...new Set(
      detections
        .map((d) => String(d.sensitive_type ?? "").trim())
        .filter(Boolean)
        .map((t) => sanitizeString(t)),
    ),
  ];

  const maskedValues = detections
    .map((d) => sanitizeString(String(d.masked_value ?? "")))
    .filter(Boolean);

  const retestIds = verification?.evidence_used ?? [];

  return (
    <Card title="Before / after fix verification">
      <div className="grid gap-6 md:grid-cols-2">
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
            Before
          </h3>
          <ul className="space-y-1 text-sm text-slate-800">
            <li>
              <span className="text-slate-500">Detected sensitive types: </span>
              {sensitiveTypes.length ? sensitiveTypes.join(", ") : "—"}
            </li>
            <li>
              <span className="text-slate-500">Masked values: </span>
              {maskedValues.length ? maskedValues.join("; ") : "—"}
            </li>
            <li>
              <span className="text-slate-500">Affected endpoint: </span>
              {sanitizeString(incident.affected_endpoint ?? "—")}
            </li>
            <li>
              <span className="text-slate-500">Affected service: </span>
              {sanitizeString(incident.affected_service ?? "—")}
            </li>
          </ul>
        </section>

        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
            After
          </h3>
          {verification ? (
            <ul className="space-y-1 text-sm text-slate-800">
              <li className="flex items-center gap-2">
                <span className="text-slate-500">Verification status:</span>
                <StatusBadge value={verification.verification_status} />
              </li>
              <li>
                <span className="text-slate-500">Retest evidence IDs: </span>
                {retestIds.length ? retestIds.join(", ") : "—"}
              </li>
              <li>
                <span className="text-slate-500">Passed checks: </span>
                {(verification.passed_checks ?? []).join(", ") || "—"}
              </li>
              <li>
                <span className="text-slate-500">Failed checks: </span>
                {(verification.failed_checks ?? []).join(", ") || "—"}
              </li>
            </ul>
          ) : (
            <p className="text-sm text-slate-600">No fix verification recorded yet.</p>
          )}
        </section>
      </div>

      <p className="mt-4 text-xs text-slate-500">
        {humanReviewRequired
          ? "Human review is still required before closure. Verification does not automatically close the incident."
          : "Human review is required before closure. Verification does not automatically close the incident."}
      </p>
    </Card>
  );
}
