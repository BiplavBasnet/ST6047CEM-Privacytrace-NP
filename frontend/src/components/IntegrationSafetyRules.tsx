const REJECTED_TYPES = [
  "Raw Nepali phone numbers",
  "Raw wallet IDs",
  "Raw JWT strings",
  "Bearer tokens / Authorization headers",
  "Raw API keys",
  "Private keys",
  "Plaintext passwords / password hashes",
  "Unmasked session tokens",
];

const REJECTED_PHRASES = [
  "Claims of certainty about causation",
  "Claims assigning blame",
  "Guaranteed-causation claims",
  "Definitive attribution wording",
  "Personal fault attribution",
  "Claims of certain remediation",
  "Automatic closure claims",
];

/**
 * Static reference list shown on the Integrations page so SOC users
 * know up-front what inbound safety validation will reject. The lists
 * mirror `audit_safety_service.scan_text_for_sensitive` and
 * `scan_text_for_overclaim` on the backend.
 */
export default function IntegrationSafetyRules() {
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <section>
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-600">
          Rejected if payload contains
        </h3>
        <ul className="mt-2 space-y-1 text-xs text-slate-700">
          {REJECTED_TYPES.map((item) => (
            <li key={item} className="flex items-start gap-2">
              <span aria-hidden="true" className="mt-1 inline-block size-1.5 rounded-full bg-red-500" />
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </section>
      <section>
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-600">
          Rejected overclaim categories
        </h3>
        <ul className="mt-2 space-y-1 text-xs text-slate-700">
          {REJECTED_PHRASES.map((item) => (
            <li key={item} className="flex items-start gap-2">
              <span aria-hidden="true" className="mt-1 inline-block size-1.5 rounded-full bg-amber-500" />
              <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-xs">
                {item}
              </code>
            </li>
          ))}
        </ul>
      </section>
      <p className="sm:col-span-2 text-xs text-slate-500">
        Rejections are audited; the rejected payload is never echoed back to the
        caller or stored in plain text.
      </p>
    </div>
  );
}
