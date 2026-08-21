import { useState } from "react";
import { FileCheck2, FileWarning } from "lucide-react";
import Card from "../../components/Card";
import FinalReportExportPanel from "../../components/FinalReportExportPanel";
import { SegmentedTabs } from "../../components/ui/primitives";
import { sanitizeString } from "../../utils/safety";
import type { IncidentWorkspaceData } from "./types";

const CHECK_LABELS: Record<string, string> = {
  incident_summary_ready: "Incident summary ready",
  root_cause_available: "Root-cause analysis available",
  human_review_recorded: "Human review recorded",
  remediation_recorded: "Remediation action recorded",
  retest_evidence_available: "Retest evidence available",
  fix_verification_available: "Fix verification available",
  limitations_available: "Confidence limitations available",
};

export default function IncidentReportPage({
  data,
  canExport,
}: {
  data: IncidentWorkspaceData;
  canExport: boolean;
}) {
  const ready = data.readiness.report_ready;
  const [tab, setTab] = useState("summary");
  return (
    <>
      <Card title="Final investigation report">
        <div className={`mb-4 flex items-start gap-3 rounded-md border p-3 ${ready ? "border-teal-200 bg-teal-50 text-teal-900" : "border-amber-200 bg-amber-50 text-amber-950"}`}>
          {ready ? <FileCheck2 className="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true" /> : <FileWarning className="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true" />}
          <div>
            <p className="font-semibold">{sanitizeString(data.readiness.report_label)}</p>
            {!ready ? <p className="mt-1 text-xs">Export remains available with an incomplete-stage label.</p> : null}
          </div>
        </div>
        <FinalReportExportPanel incidentId={data.incident.incident_id} canExport={canExport} />
        {!canExport ? <p className="mt-2 text-sm text-ink-muted">Your role cannot export reports.</p> : null}
      </Card>
      <SegmentedTabs
        tabs={[
          { id: "summary", label: "Summary" },
          { id: "verification", label: "Verification" },
          { id: "provenance", label: "Provenance" },
          { id: "history", label: "History" },
        ]}
        value={tab}
        onChange={setTab}
      />
      <div className={tab === "history" ? "hidden" : "mt-3"}>
        <ul data-testid="report-readiness" className="grid gap-2 text-sm sm:grid-cols-2 lg:grid-cols-3">
          {Object.entries(data.readiness.checks)
            .filter(([key]) => {
              if (tab === "verification") return key.includes("retest") || key.includes("fix_verification");
              if (tab === "provenance") return key.includes("limitations");
              return true;
            })
            .map(([key, value]) => (
            <li key={key} className={`rounded-md border p-3 ${value ? "border-slate-200 text-navy-900" : "border-amber-200 text-amber-900"}`}>
              <span className="font-medium">{value ? "Complete" : "Incomplete"}</span>
              <span className="block text-xs">{CHECK_LABELS[key] ?? key.replaceAll("_", " ")}</span>
            </li>
          ))}
        </ul>
        {tab === "summary" && data.readiness.blocking_items.length ? (
          <div className="mt-4">
            <p className="text-xs font-medium uppercase text-ink-subtle">Blocking items</p>
            <ul className="mt-1 list-inside list-disc text-sm text-navy-900">
              {data.readiness.blocking_items.map((item) => <li key={item}>{sanitizeString(item)}</li>)}
            </ul>
          </div>
        ) : null}
        {tab === "summary" && data.readiness.warning_items.length ? (
          <ul className="mt-3 list-inside list-disc text-sm text-amber-800">
            {data.readiness.warning_items.map((item) => <li key={item}>{sanitizeString(item)}</li>)}
          </ul>
        ) : null}
        <p className="mt-4 text-sm text-ink-muted">Incident disposition remains a human decision and is not performed automatically.</p>
      </div>
      {tab === "history" ? (
        <div className="mt-3">
          {data.reports.length ? (
            <ul className="space-y-1 text-sm text-navy-900">
              {data.reports.slice(0, 10).map((report) => (
                <li key={report.report_id}>{report.created_at}: {sanitizeString(report.report_type)}</li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-ink-muted">No generated report history is stored yet.</p>
          )}
        </div>
      ) : null}
    </>
  );
}
