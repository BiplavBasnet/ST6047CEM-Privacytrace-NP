import type { ScannerEvidenceSafeRead } from "../api/scannerBridgeClient";
import { sanitizeString } from "../utils/safety";

interface Props {
  records: ScannerEvidenceSafeRead[];
}

export default function ScannerEvidenceTable({ records }: Props) {
  if (records.length === 0) {
    return <p className="text-sm text-slate-500">No scanner evidence imported yet.</p>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-left text-xs">
        <thead className="border-b text-slate-600">
          <tr>
            <th className="py-1 pr-3">ID</th>
            <th className="py-1 pr-3">Format</th>
            <th className="py-1 pr-3">Masked value</th>
            <th className="py-1 pr-3">Causal score</th>
            <th className="py-1 pr-3">Incident</th>
          </tr>
        </thead>
        <tbody>
          {records.map((row) => (
            <tr key={row.scanner_evidence_id} className="border-b border-slate-100">
              <td className="py-1 pr-3 font-mono">{sanitizeString(row.scanner_evidence_id)}</td>
              <td className="py-1 pr-3">{sanitizeString(row.source_format)}</td>
              <td className="py-1 pr-3 font-mono">{sanitizeString(row.masked_value ?? "—")}</td>
              <td className="py-1 pr-3">
                {row.causal_relevance_score != null
                  ? row.causal_relevance_score.toFixed(2)
                  : "—"}
              </td>
              <td className="py-1 pr-3">{sanitizeString(row.linked_incident_id ?? "—")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
