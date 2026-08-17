import Card from "../Card";

export default function ScannerComparisonPanel() {
  return (
    <Card title="Basic scanner vs PrivacyTrace-NP">
      <div className="grid gap-6 md:grid-cols-2">
        <section>
          <h3 className="mb-2 text-sm font-semibold text-slate-800">Basic scanner</h3>
          <ul className="list-inside list-disc space-y-1 text-sm text-slate-700">
            <li>Detects sensitive pattern</li>
            <li>May show alert</li>
            <li>Limited evidence linking</li>
            <li>No likely root-cause ranking</li>
            <li>No human review workflow</li>
            <li>No fix verification</li>
          </ul>
        </section>
        <section>
          <h3 className="mb-2 text-sm font-semibold text-slate-800">PrivacyTrace-NP</h3>
          <ul className="list-inside list-disc space-y-1 text-sm text-slate-700">
            <li>Detects and masks sensitive values</li>
            <li>Links evidence IDs</li>
            <li>Ranks likely technical causes</li>
            <li>Shows missing evidence</li>
            <li>Supports guarded explanation</li>
            <li>Records human review</li>
            <li>Verifies fix using retest evidence</li>
            <li>Generates safe reports and thesis metrics</li>
          </ul>
        </section>
      </div>
      <p className="mt-3 text-xs text-slate-500">
        Comparison is descriptive only. No invented performance numbers are shown.
      </p>
    </Card>
  );
}
