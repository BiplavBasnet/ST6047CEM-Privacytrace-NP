import PageHeader from "../components/PageHeader";
import ScannerComparisonPanel from "../components/differentiation/ScannerComparisonPanel";

/** Short description of what PrivacyTrace-NP is — and what it is not. */
export default function AboutPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        breadcrumbs={[{ label: "Dashboard", to: "/" }, { label: "About" }]}
        title="About PrivacyTrace-NP"
        description="Live privacy monitoring and incident traceability for masked API log exposure."
      />

      <section>
        <h2 className="text-sm font-semibold text-navy-900">What it does</h2>
        <ul className="mt-2 list-inside list-disc space-y-1 text-sm text-navy-900">
          <li>Provides near-real-time, masked privacy alerts through passive log/event ingestion.</li>
          <li>Ingests evidence (logs, scan reports, access events) and masks sensitive values before storage or display.</li>
          <li>Ranks likely root causes with confidence bands based on available supporting evidence.</li>
          <li>Requires human review before any incident is confirmed.</li>
          <li>Verifies fixes using retest evidence.</li>
          <li>Generates privacy-safe final reports (PDF/HTML/JSON/CSV/ZIP).</li>
        </ul>
      </section>

      <section>
        <h2 className="text-sm font-semibold text-navy-900">What it does not do</h2>
        <ul className="mt-2 list-inside list-disc space-y-1 text-sm text-navy-900">
          <li>It does not prove root cause or assign blame — rankings are likely causes that require human review.</li>
          <li>It does not block or modify API traffic; ingestion is passive.</li>
          <li>It complements existing monitoring platforms and does not act as a firewall.</li>
          <li>It does not display, store or export raw sensitive values.</li>
          <li>It does not guarantee privacy leak prevention; it supports investigation.</li>
        </ul>
      </section>

      <details className="border-t border-slate-200/90 py-3">
        <summary className="cursor-pointer text-sm font-semibold text-navy-800">Scanner comparison</summary>
        <div className="mt-3">
          <ScannerComparisonPanel />
        </div>
      </details>

      <p className="rounded-md border border-slate-200 bg-surface-raised px-3 py-2 text-xs text-ink-muted">
        Thesis prototype for academic demonstration. Deployment in a real
        environment requires environment-specific configuration and validation.
      </p>
    </div>
  );
}
