import type { ScannerPreviewResponse } from "../api/scannerBridgeClient";
import { sanitizeString } from "../utils/safety";

interface Props {
  preview: ScannerPreviewResponse | null;
}

export default function ScannerPreviewPanel({ preview }: Props) {
  if (!preview) {
    return (
      <p className="text-sm text-slate-500">
        Run a preview to see safe, masked findings before import.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      <p className="text-sm text-slate-700">
        Format: <span className="font-mono">{sanitizeString(preview.detected_format)}</span>
        {" · "}
        Import allowed: {preview.import_allowed ? "yes" : "no"}
        {" · "}
        Unsafe items: {preview.unsafe_item_count}
      </p>
      {preview.warnings.length > 0 ? (
        <ul className="text-xs text-amber-800">
          {preview.warnings.map((w) => (
            <li key={w}>{sanitizeString(w)}</li>
          ))}
        </ul>
      ) : null}
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-xs">
          <thead className="border-b text-slate-600">
            <tr>
              <th className="py-1 pr-3">Detector</th>
              <th className="py-1 pr-3">Masked value</th>
              <th className="py-1 pr-3">File</th>
              <th className="py-1 pr-3">Severity</th>
            </tr>
          </thead>
          <tbody>
            {preview.safe_preview_findings.map((row, idx) => (
              <tr key={idx} className="border-b border-slate-100">
                <td className="py-1 pr-3">{sanitizeString(row.detector_name ?? "—")}</td>
                <td className="py-1 pr-3 font-mono">
                  {sanitizeString(row.masked_value ?? "—")}
                </td>
                <td className="py-1 pr-3">{sanitizeString(row.source_file ?? "—")}</td>
                <td className="py-1 pr-3">{sanitizeString(row.severity ?? "—")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
