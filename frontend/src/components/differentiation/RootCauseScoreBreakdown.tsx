import Card from "../Card";
import { sanitizeString } from "../../utils/safety";

export default function RootCauseScoreBreakdown({
  breakdown,
}: {
  breakdown: Record<string, unknown>[];
}) {
  return (
    <Card title="Root-cause score breakdown">
      {!breakdown.length ? (
        <p className="text-sm text-slate-600">No score breakdown available.</p>
      ) : (
        <ul className="space-y-2 text-sm">
          {breakdown.map((item, idx) => (
            <li key={idx} className="rounded border border-slate-200 p-2">
              <p className="font-medium">{sanitizeString(String(item.signal_name ?? "signal"))}</p>
              <p>Weight: {sanitizeString(String(item.weight ?? "0"))}</p>
              <p>Matched: {String(Boolean(item.matched))}</p>
              <p>{sanitizeString(String(item.reason ?? ""))}</p>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
