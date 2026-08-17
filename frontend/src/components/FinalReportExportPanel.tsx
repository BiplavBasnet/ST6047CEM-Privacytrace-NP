import { useState } from "react";
import { downloadFinalReport } from "../api/finalReportClient";
import ReportDownloadButton from "./ReportDownloadButton";

type FinalReportExportPanelProps = {
  incidentId: string;
  canExport: boolean;
};

export default function FinalReportExportPanel({
  incidentId,
  canExport,
}: FinalReportExportPanelProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleDownload(
    format: "pdf" | "html" | "json" | "csv" | "zip",
  ) {
    setBusy(true);
    setError(null);
    try {
      await downloadFinalReport(incidentId, format);
    } catch {
      setError("The report could not be generated. Check incident readiness and try again.");
    } finally {
      setBusy(false);
    }
  }

  if (!canExport) return null;

  return (
    <div className="space-y-3" data-testid="final-report-export-panel">
      <p className="text-xs text-slate-600">PDF is recommended for review; ZIP contains the full privacy-safe bundle.</p>
      <div className="flex flex-wrap gap-2">
        <ReportDownloadButton
          label="Download PDF"
          primary
          disabled={busy}
          onClick={() => handleDownload("pdf")}
        />
        <ReportDownloadButton
          label="Download ZIP Bundle"
          disabled={busy}
          onClick={() => handleDownload("zip")}
        />
      </div>
      <details data-testid="advanced-report-formats">
        <summary className="cursor-pointer text-xs font-medium text-navy-700">
          Advanced export formats
        </summary>
        <div className="mt-3 flex flex-wrap gap-2">
          <ReportDownloadButton
            label="Download HTML"
            disabled={busy}
            onClick={() => handleDownload("html")}
          />
          <ReportDownloadButton
            label="Download JSON"
            disabled={busy}
            onClick={() => handleDownload("json")}
          />
          <ReportDownloadButton
            label="Download Evidence CSV"
            disabled={busy}
            onClick={() => handleDownload("csv")}
          />
        </div>
      </details>
      {error ? <p className="text-xs text-red-600">{error}</p> : null}
    </div>
  );
}
