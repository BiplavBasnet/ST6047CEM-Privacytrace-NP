import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import CollapsibleSection from "../components/CollapsibleSection";
import PageHeader from "../components/PageHeader";

interface GuideSection {
  title: string;
  body: string[];
  link?: { label: string; to: string };
}

const SECTIONS: GuideSection[] = [
  {
    title: "What PrivacyTrace-NP does",
    body: [
      "PrivacyTrace-NP is a live privacy monitoring and incident traceability framework for detecting possible sensitive data exposure in API log/event streams, masking values, creating privacy alerts, correlating evidence, ranking likely root causes, supporting human review, verifying fixes, and exporting privacy-safe reports.",
    ],
  },
  {
    title: "What it does not do",
    body: [
      "It does not prove root cause or assign blame — rankings are likely causes that require human review.",
      "It does not change production code. It records recommended remediation actions only.",
      "It does not block API traffic or guarantee privacy leak prevention. It complements existing monitoring platforms.",
      "It never displays, stores or exports raw sensitive values.",
    ],
  },
  {
    title: "Main workflow",
    body: [
      "Live event stream -> masked privacy alert -> create or link incident -> review traceability and evidence strength -> complete human review -> record remediation action -> add retest evidence -> run fix verification -> generate the final report.",
    ],
    link: { label: "Open Guided Demo", to: "/help/demo" },
  },
  {
    title: "Evidence Import",
    body: [
      "This is the secondary path for historical logs, supporting evidence, retest evidence, controlled investigation and repeatable evaluation. Load synthetic demo evidence or upload sanitised evidence, then continue through the same incident workflow.",
    ],
    link: { label: "Open Evidence", to: "/evidence" },
  },
  {
    title: "Live Privacy Monitor",
    body: [
      "For near-real-time privacy alerting from copied log/event streams. Send a synthetic test event or receive a live event; a masked alert is created, which you can link or convert into an incident that follows the same workflow.",
      "Live alerts are symptom and timeline evidence. CI/CD, deployment, code/config or scanner evidence is needed before root-cause evidence strength can become strong.",
    ],
    link: { label: "Open Live Privacy Monitor", to: "/live-monitor" },
  },
  {
    title: "Incident Overview",
    body: [
      "The first screen of an incident explains what happened, where, what sensitive data type was detected (masked), the top likely cause with a confidence band, what evidence supports or is missing, and the next recommended action.",
    ],
    link: { label: "View Incidents", to: "/incidents" },
  },
  {
    title: "Traceability",
    body: [
      "Shows the trace summary, masked detections, evidence chain, root-cause ranking with score breakdown, contradicting or weakening evidence, and missing evidence suggestions.",
      "Root-cause ranking is based on available evidence. It is not proof. Human review is required.",
    ],
  },
  {
    title: "Human Review",
    body: [
      "Human review is the decision point where a responsible analyst accepts the likely cause for remediation, requests more evidence, declines a false positive, or escalates the incident.",
      "Every decision requires a written reason. Accepting the likely cause does not mean the incident is fixed — fix verification is still required.",
    ],
  },
  {
    title: "Remediation Action",
    body: [
      "PrivacyTrace-NP records what must be changed outside the tool — for example updating logging middleware, masking query parameters or authorization headers, updating redaction rules, or reviewing debug/proxy logging.",
      "After implementation, run an allowlisted persisted test and record an explicit controlled retest. Imported fixed logs alone do not enable fix verification.",
    ],
  },
  {
    title: "Fix Verification",
    body: [
      "Checks the exact current implementation, persisted allowlisted test and controlled retest chain against the original server-backed dimensions.",
      "Verification passed based on available retest evidence; failed because sensitive values still appear; or inconclusive because retest evidence is missing or incomplete. It never claims permanent or certain remediation.",
    ],
  },
  {
    title: "Final Report",
    body: [
      "The final output: incident summary, masked detections, evidence chain, likely cause with confidence level, missing evidence, human review decision, remediation action, fix verification status, limitations and privacy controls.",
      "PDF is recommended for viva and client review; ZIP contains the complete privacy-safe bundle. All exports exclude raw sensitive values.",
    ],
    link: { label: "Open Final Reports", to: "/reports" },
  },
  {
    title: "Roles and permissions",
    body: [
      "Admin: full workflow access. Security Analyst: reviews incidents, makes decisions, creates reports and incidents from alerts. DevSecOps Engineer: monitors alerts, creates/links incidents, records remediation. Auditor: read-only access to incidents, evidence, audit trail and reports. Developer/Viewer: restricted access.",
      "The backend enforces every permission; the interface additionally hides actions your role cannot perform.",
    ],
  },
  {
    title: "Safety and masking",
    body: [
      "All sensitive values are masked before storage or display — for example 984****567, WALLET-NP-****, TXN-NP-2026-****, jwt_[masked]. Raw values never appear in dashboards, reports, exports, logs or this guide.",
    ],
  },
  {
    title: "Common errors",
    body: [
      "Backend unavailable: check that the FastAPI server is running.",
      "Permission denied: your role cannot perform that action — the message names the required role.",
      "Incident not found: return to the incident list.",
      "Report could not be generated: try again or check incident evidence. No sensitive values are exposed by errors.",
    ],
  },
  {
    title: "Demo walkthrough",
    body: [
      "For a five-minute scripted demo (login details, suggested clicks, expected results), open the Demo Guide.",
    ],
    link: { label: "Open Demo Guide", to: "/help/demo" },
  },
];

const GROUPS: { heading: string; titles: string[] }[] = [
  { heading: "Getting started", titles: ["What PrivacyTrace-NP does", "What it does not do", "Demo walkthrough"] },
  { heading: "Main workflow", titles: ["Main workflow", "Live Privacy Monitor", "Incident Overview", "Traceability", "Human Review", "Remediation Action", "Fix Verification", "Final Report"] },
  { heading: "Common tasks", titles: ["Evidence Import", "Roles and permissions"] },
  { heading: "Safety and terminology", titles: ["Safety and masking"] },
  { heading: "Troubleshooting", titles: ["Common errors"] },
];

/** In-app user guide mirroring docs/USER_GUIDE.md in plain language. */
export default function UserGuidePage() {
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return SECTIONS;
    return SECTIONS.filter((section) =>
      [section.title, ...section.body].join(" ").toLowerCase().includes(needle),
    );
  }, [query]);

  return (
    <div className="space-y-6">
      <PageHeader
        breadcrumbs={[{ label: "Dashboard", to: "/" }, { label: "User Guide" }]}
        title="User Guide"
        description="How to use PrivacyTrace-NP from login to final report, in plain language."
      />
      <label className="block max-w-md text-sm text-navy-900">
        Search the guide
        <input
          className="field-control mt-1 w-full"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Find a topic"
        />
      </label>
      <nav className="flex flex-wrap gap-3 text-sm" aria-label="Guide topics">
        {GROUPS.map((group) => (
          <a key={group.heading} href={`#${group.heading.replaceAll(" ", "-").toLowerCase()}`} className="font-semibold text-accent hover:underline">
            {group.heading}
          </a>
        ))}
      </nav>
      {query.trim() ? (
        <div className="space-y-2">
          {filtered.map((section) => (
            <GuideItem key={section.title} section={section} defaultOpen />
          ))}
        </div>
      ) : (
        GROUPS.map((group) => (
          <section key={group.heading} id={group.heading.replaceAll(" ", "-").toLowerCase()}>
            <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-ink-subtle">{group.heading}</h2>
            <div className="space-y-1">
              {group.titles.map((title) => {
                const section = SECTIONS.find((item) => item.title === title);
                return section ? <GuideItem key={title} section={section} /> : null;
              })}
            </div>
          </section>
        ))
      )}
      <p className="flex flex-wrap gap-3 text-sm">
        <Link to="/help/demo" className="font-semibold text-accent hover:underline">Demo Guide</Link>
        <Link to="/help/about" className="font-semibold text-accent hover:underline">About</Link>
        <Link to="/metrics" className="font-semibold text-accent hover:underline">Metrics</Link>
        <Link to="/security" className="font-semibold text-accent hover:underline">Security</Link>
        <Link to="/taxonomy" className="font-semibold text-accent hover:underline">Taxonomy</Link>
      </p>
    </div>
  );
}

function GuideItem({ section, defaultOpen = false }: { section: GuideSection; defaultOpen?: boolean }) {
  return (
    <CollapsibleSection summary={section.title} defaultOpen={defaultOpen}>
      {section.body.map((paragraph) => (
        <p key={paragraph.slice(0, 40)} className="mb-2 text-sm text-navy-900">
          {paragraph}
        </p>
      ))}
      {section.link ? (
        <Link to={section.link.to} className="text-sm font-medium text-accent hover:underline">
          {section.link.label} →
        </Link>
      ) : null}
    </CollapsibleSection>
  );
}
