import {
  clearAuthToken,
  getAuthToken,
  notifySessionExpired,
} from "./authClient";
import { getApiBaseUrl } from "./client";

export type FinalReportFormat = "pdf" | "html" | "json" | "csv" | "zip";

const PATHS: Record<FinalReportFormat, string> = {
  pdf: "final-report.pdf",
  html: "final-report.html",
  json: "final-report.json",
  csv: "evidence-summary.csv",
  zip: "final-report-bundle.zip",
};

const FILENAMES: Record<FinalReportFormat, string> = {
  pdf: "final-investigation-report.pdf",
  html: "final-investigation-report.html",
  json: "final-investigation-report.json",
  csv: "evidence-summary.csv",
  zip: "final-report-bundle.zip",
};

export async function downloadFinalReport(
  incidentId: string,
  format: FinalReportFormat,
): Promise<void> {
  const token = getAuthToken();
  const path = `/reports/incidents/${encodeURIComponent(incidentId)}/${PATHS[format]}`;
  const response = await fetch(`${getApiBaseUrl()}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      if (typeof body?.detail === "string") {
        detail = body.detail;
      }
    } catch {
      /* ignore */
    }
    if (response.status === 401) {
      clearAuthToken();
      notifySessionExpired();
    }
    throw new Error(detail);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${incidentId}-${FILENAMES[format]}`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}
