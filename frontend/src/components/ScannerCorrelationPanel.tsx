import type { ScannerCorrelationResponse } from "../api/scannerBridgeClient";
import { sanitizeString } from "../utils/safety";

interface Props {
  correlation: ScannerCorrelationResponse | null;
}

function Bucket({
  title,
  items,
}: {
  title: string;
  items: ScannerCorrelationResponse["strong_supporting_evidence"];
}) {
  if (items.length === 0) return null;
  return (
    <section>
      <h4 className="text-xs font-semibold text-slate-700">{title}</h4>
      <ul className="mt-1 space-y-1 text-xs text-slate-600">
        {items.map((item) => (
          <li key={item.scanner_evidence_id}>
            <span className="font-mono">{sanitizeString(item.scanner_evidence_id)}</span>
            {" · score "}
            {item.causal_relevance_score.toFixed(2)}
            {item.masked_value ? ` · ${sanitizeString(item.masked_value)}` : ""}
          </li>
        ))}
      </ul>
    </section>
  );
}

export default function ScannerCorrelationPanel({ correlation }: Props) {
  if (!correlation) {
    return (
      <p className="text-sm text-slate-500">
        Correlate imported evidence against an incident to rank supporting signals.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      <p className="text-sm text-slate-700">{sanitizeString(correlation.summary)}</p>
      {correlation.human_review_required ? (
        <p className="rounded-md bg-amber-50 px-2 py-1 text-xs text-amber-900">
          Human review required — scanner findings are supporting evidence only.
        </p>
      ) : null}
      <Bucket title="Strong supporting evidence" items={correlation.strong_supporting_evidence} />
      <Bucket title="Moderate supporting evidence" items={correlation.moderate_supporting_evidence} />
      <Bucket title="Weak supporting evidence" items={correlation.weak_supporting_evidence} />
      {correlation.missing_context.length > 0 ? (
        <p className="text-xs text-slate-500">
          Missing context: {correlation.missing_context.map(sanitizeString).join(", ")}
        </p>
      ) : null}
    </div>
  );
}
