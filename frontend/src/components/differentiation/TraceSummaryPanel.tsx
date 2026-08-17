import Card from "../Card";
import { sanitizeString } from "../../utils/safety";

export default function TraceSummaryPanel({
  summary,
  reviewerWarning,
}: {
  summary: Record<string, unknown> | undefined;
  reviewerWarning?: string;
}) {
  const why = (summary?.why_ranked_highest as unknown[]) ?? [];
  const missing = (summary?.what_is_missing as unknown[]) ?? [];
  return (
    <Card title="Trace summary">
      <p className="text-sm">{sanitizeString(String(summary?.what_happened ?? "—"))}</p>
      <p className="text-sm mt-1">Where: {sanitizeString(String(summary?.where_it_happened ?? "—"))}</p>
      <p className="text-sm mt-1">
        Strongest likely cause: {sanitizeString(String(summary?.strongest_likely_cause ?? "—"))}
      </p>
      <ul className="mt-2 list-disc pl-5 text-sm">
        {why.map((item, idx) => (
          <li key={idx}>{sanitizeString(String(item))}</li>
        ))}
      </ul>
      <p className="mt-2 text-sm font-medium">Missing evidence:</p>
      <ul className="list-disc pl-5 text-sm">
        {missing.map((item, idx) => (
          <li key={idx}>{sanitizeString(String(item))}</li>
        ))}
      </ul>
      <p className="mt-2 text-sm">{sanitizeString(String(summary?.safe_conclusion ?? ""))}</p>
      <p className="mt-2 text-xs text-slate-500">{sanitizeString(reviewerWarning ?? "")}</p>
    </Card>
  );
}
