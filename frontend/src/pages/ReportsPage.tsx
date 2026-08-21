import { Download, ExternalLink } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type IncidentReportSummary, type ReportReadiness } from "../api/client";
import { downloadFinalReport } from "../api/finalReportClient";
import Card from "../components/Card";
import CollapsibleSection from "../components/CollapsibleSection";
import FinalReportExportPanel from "../components/FinalReportExportPanel";
import PageHeader from "../components/PageHeader";
import { ErrorState, LoadingState } from "../components/LoadingError";
import { useAuth } from "../context/AuthContext";
import { sanitizeString } from "../utils/safety";

interface RecentReport extends IncidentReportSummary {
  incidentId: string;
  readiness: ReportReadiness | null;
}

export default function ReportsPage() {
  const { can } = useAuth();
  const [searchParams] = useSearchParams();
  const selectedIncident = searchParams.get("incident")?.trim() || null;
  const [recentReports, setRecentReports] = useState<RecentReport[]>([]);
  const [selectedReadiness, setSelectedReadiness] = useState<ReportReadiness | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [downloadBusy, setDownloadBusy] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    (async () => {
      try {
        const incidents = await api.listIncidents();
        const reportResults = await Promise.allSettled(
          incidents.slice(0, 40).map(async (incident) => {
            const [reports, readiness] = await Promise.all([
              api.listReports(incident.incident_id),
              api.getReportReadiness(incident.incident_id).catch(() => null),
            ]);
            return reports.reports.map((report) => ({
              ...report,
              incidentId: incident.incident_id,
              readiness,
            }));
          }),
        );
        if (cancelled) return;
        const rows = reportResults
          .flatMap((result) => result.status === "fulfilled" ? result.value : [])
          .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
        setRecentReports(rows);
        if (selectedIncident) {
          setSelectedReadiness(await api.getReportReadiness(selectedIncident));
        } else {
          setSelectedReadiness(null);
        }
      } catch (reason) {
        if (!cancelled) setError(reason instanceof Error ? reason.message : "Failed to load reports");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [selectedIncident]);

  async function download(incidentId: string, format: "pdf" | "zip") {
    setDownloadBusy(`${incidentId}-${format}`);
    setError(null);
    try {
      await downloadFinalReport(incidentId, format);
    } catch {
      setError("The report could not be downloaded.");
    } finally {
      setDownloadBusy(null);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        breadcrumbs={[{ label: "Dashboard", to: "/" }, { label: "Reports" }]}
        title="Reports"
        description="Open recent privacy-safe reports or continue an incident report workflow."
      />

      {loading ? <LoadingState message="Loading report index..." /> : null}
      {error ? <ErrorState message={error} /> : null}

      {selectedIncident ? (
        <Card title={`Final Investigation Report - ${selectedIncident}`}>
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className={`text-sm font-semibold ${selectedReadiness?.report_ready ? "text-teal-800" : "text-amber-800"}`}>
                {sanitizeString(selectedReadiness?.report_label ?? "Readiness unavailable")}
              </p>
              <Link to={`/incidents/${encodeURIComponent(selectedIncident)}/report`} className="mt-1 inline-flex items-center gap-1 text-sm font-medium text-accent hover:underline">
                Open Incident Final Report <ExternalLink className="h-4 w-4" aria-hidden="true" />
              </Link>
            </div>
          </div>
          <FinalReportExportPanel incidentId={selectedIncident} canExport={can("report:generate")} />
        </Card>
      ) : null}

      {selectedReadiness ? (
        <CollapsibleSection summary="Report readiness checklist">
          <ul data-testid="reports-readiness" className="grid gap-2 text-sm sm:grid-cols-2 lg:grid-cols-3">
            {Object.entries(selectedReadiness.checks).map(([key, complete]) => (
              <li
                key={key}
                className={`rounded-lg border p-3 ${
                  complete
                    ? "border-slate-200 bg-surface-raised/50"
                    : "border-amber-200 bg-amber-50/80 text-amber-900"
                }`}
              >
                <span className="font-semibold">{complete ? "Complete" : "Incomplete"}</span>
                <span className="mt-0.5 block text-xs capitalize text-ink-muted">
                  {key.replaceAll("_", " ")}
                </span>
              </li>
            ))}
          </ul>
        </CollapsibleSection>
      ) : null}

      <Card title="Recent Reports">
        {recentReports.length ? (
          <div className="-mx-5 -mb-5 overflow-x-auto sm:-mx-6">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Incident</th>
                  <th>Status</th>
                  <th>Generated</th>
                  <th>PDF</th>
                  <th>ZIP</th>
                </tr>
              </thead>
              <tbody>
                {recentReports.slice(0, 30).map((report) => (
                  <tr key={`${report.incidentId}-${report.report_id}`}>
                    <td>
                      <Link
                        to={`/incidents/${encodeURIComponent(report.incidentId)}/report`}
                        className="mono-id text-accent hover:text-teal-800"
                      >
                        {report.incidentId}
                      </Link>
                    </td>
                    <td>
                      <span
                        className={`inline-flex rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                          report.readiness?.report_ready
                            ? "bg-teal-50 text-teal-800 ring-1 ring-inset ring-teal-600/15"
                            : "bg-slate-100 text-slate-600 ring-1 ring-inset ring-slate-500/15"
                        }`}
                      >
                        {report.readiness?.report_ready ? "Final ready" : "Draft"}
                      </span>
                    </td>
                    <td className="text-xs text-ink-muted">{report.created_at}</td>
                    <td>
                      <DownloadButton
                        label="PDF"
                        busy={downloadBusy === `${report.incidentId}-pdf`}
                        disabled={!can("report:generate")}
                        onClick={() => download(report.incidentId, "pdf")}
                      />
                    </td>
                    <td>
                      <DownloadButton
                        label="ZIP"
                        busy={downloadBusy === `${report.incidentId}-zip`}
                        disabled={!can("report:generate")}
                        onClick={() => download(report.incidentId, "zip")}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="rounded-lg border border-dashed border-slate-300 bg-surface-raised/80 px-6 py-8 text-center">
            <p className="text-sm font-semibold text-navy-900">No generated report history is available.</p>
            <Link to="/incidents" className="btn-secondary mt-4 inline-flex">
              Open an incident to generate a report
            </Link>
          </div>
        )}
      </Card>
    </div>
  );
}

function DownloadButton({ label, busy, disabled, onClick }: { label: string; busy: boolean; disabled: boolean; onClick: () => void }) {
  return (
    <button type="button" onClick={onClick} disabled={busy || disabled} title={`Download ${label}`} className="inline-flex items-center gap-1 text-sm font-medium text-accent hover:underline disabled:text-slate-400">
      <Download className="h-4 w-4" aria-hidden="true" /> {busy ? "Preparing" : label}
    </button>
  );
}
