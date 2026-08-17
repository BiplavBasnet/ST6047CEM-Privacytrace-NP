import Card from "../Card";
import { sanitizeString } from "../../utils/safety";

export default function MissingEvidenceSuggestions({
  suggestions,
}: {
  suggestions: Record<string, unknown>[];
}) {
  return (
    <Card title="Missing evidence suggestions">
      {!suggestions.length ? (
        <p className="text-sm text-slate-600">No suggestions available.</p>
      ) : (
        <ul className="space-y-2 text-sm">
          {suggestions.map((item, idx) => (
            <li key={idx}>
              <p className="font-medium">{sanitizeString(String(item.missing_evidence ?? ""))}</p>
              <p className="text-slate-700">{sanitizeString(String(item.suggested_action ?? ""))}</p>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
