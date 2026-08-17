import Card from "../Card";
import { sanitizeString } from "../../utils/safety";

export default function ContradictingEvidencePanel({
  items,
}: {
  items: Record<string, unknown>[];
}) {
  return (
    <Card title="Contradicting evidence">
      {!items.length ? (
        <p className="text-sm text-slate-600">No contradicting evidence recorded.</p>
      ) : (
        <ul className="space-y-2 text-sm">
          {items.map((item, idx) => (
            <li key={idx}>
              <span className="font-medium">{sanitizeString(String(item.evidence_id ?? "unknown"))}</span>
              {": "}
              {sanitizeString(String(item.reason ?? ""))}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
