import { Link } from "react-router-dom";
import PageHeader from "../components/PageHeader";

const STEPS: { title: string; text: string; to?: string; linkLabel?: string }[] = [
  {
    title: "Check system status",
    text: "Confirm that the backend and database are available, then review the Live Monitor status panel.",
    to: "/",
    linkLabel: "Open Dashboard",
  },
  {
    title: "Open Live Privacy Monitor",
    text: "The default demo begins with passive, near-real-time privacy monitoring.",
    to: "/live-monitor",
    linkLabel: "Open Live Privacy Monitor",
  },
  {
    title: "Send a synthetic live event",
    text: "Use the synthetic test action. The backend applies the safety guard and returns masked values only.",
    to: "/live-monitor",
    linkLabel: "Send from Live Monitor",
  },
  {
    title: "View the privacy alert",
    text: "Open the new alert and review its service, endpoint, masked summary, evidence strength and missing evidence.",
    to: "/alerts",
    linkLabel: "Open Privacy Alerts",
  },
  {
    title: "Create an incident from the alert",
    text: "Create an incident from the selected alert in Live Monitor. The source badge should show Live Monitor.",
    to: "/live-monitor",
    linkLabel: "Create Incident",
  },
  {
    title: "Review traceability",
    text: "Open the incident and review the live alert timeline, masked detections, evidence roles and confidence limitation.",
    to: "/incidents",
    linkLabel: "View Incidents",
  },
  {
    title: "Link supporting evidence if needed",
    text: "Add CI/CD, deployment, code/config or ScannerBridge evidence when the likely-cause explanation needs stronger technical support.",
    to: "/evidence",
    linkLabel: "Open Evidence Import",
  },
  {
    title: "Complete human review",
    text: "Review the checklist and record an accountable decision. The incident cannot close automatically.",
    to: "/incidents",
    linkLabel: "Open Incident Review",
  },
  {
    title: "Record the remediation action",
    text: "Record the action accepted by the reviewer. PrivacyTrace-NP does not change production systems directly.",
  },
  {
    title: "Record a controlled retest",
    text: "After a persisted implementation and passed allowlisted test, record an explicit controlled retest with the original server-backed dimensions. Imported fixed logs alone do not unlock verification.",
    to: "/evidence?type=fixed_log",
    linkLabel: "Open Retest Import",
  },
  {
    title: "Run fix verification",
    text: "Verify the exact current controlled-retest chain and review its persisted outcome. Human review remains required.",
  },
  {
    title: "Generate the final report",
    text: "Export a privacy-safe report with the live-monitor summary, alert timeline, evidence strength, review, remediation, verification and limitations.",
    to: "/reports",
    linkLabel: "Open Reports",
  },
];

/** Short first-time walkthrough for examiners and demo viewers. */
export default function DemoGuidePage() {
  return (
    <div className="space-y-6">
      <PageHeader
        breadcrumbs={[{ label: "Dashboard", to: "/" }, { label: "Demo Guide" }]}
        title="Demo Guide"
        description="A live-first walkthrough from synthetic event to privacy alert, incident, review, retest and report."
      />
      <ol className="space-y-2">
        {STEPS.map((step, index) => (
          <li key={step.title}>
            <details className="border-t border-slate-200/90 py-3">
              <summary className="cursor-pointer text-sm font-semibold text-navy-800">
                {String(index + 1).padStart(2, "0")}. {step.title}
              </summary>
              <p className="mt-2 text-sm text-ink-muted">{step.text}</p>
              {step.to ? (
                <Link to={step.to} className="mt-2 inline-flex text-sm font-medium text-accent hover:underline">
                  {step.linkLabel} →
                </Link>
              ) : null}
            </details>
          </li>
        ))}
      </ol>
      <details className="border-t border-slate-200/90 py-3">
        <summary className="cursor-pointer text-sm font-semibold text-navy-800">Use Evidence Import instead</summary>
        <p className="mt-2 text-sm text-ink-muted">
          For historical events or controlled evaluation, start with Evidence Import and continue through the same incident, review, verification and report workflow.
        </p>
        <Link to="/evidence" className="mt-2 inline-flex text-sm font-medium text-accent hover:underline">
          Open Evidence Import
        </Link>
      </details>
      <p className="rounded-md border border-slate-200 bg-surface-raised px-3 py-2 text-xs text-ink-muted">
        All demo data is synthetic. PrivacyTrace-NP displays masked values only
        and requires human review for every incident.
      </p>
    </div>
  );
}
