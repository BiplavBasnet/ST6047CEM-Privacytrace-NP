import { useCallback, useState } from "react";
import { sanitizeString } from "../utils/safety";
import {
  SAFE_PAYLOAD_EXAMPLE,
  type IntegrationEventIngestRequest,
} from "../api/integrationsClient";

/**
 * Renders the masked-only example payload. We:
 * 1. Run `JSON.stringify` once.
 * 2. Pass the rendered string through `sanitizeString` so even if a
 *    future contributor adds a sensitive literal to the example, the
 *    UI replaces it with the safe fallback.
 * 3. Provide a copy button that uses the sanitized text.
 *
 * Nothing is ever `console.log`'d.
 */
export default function SafePayloadExample({
  data = SAFE_PAYLOAD_EXAMPLE,
}: {
  data?: IntegrationEventIngestRequest;
}) {
  const text = sanitizeString(JSON.stringify(data, null, 2));
  const [copied, setCopied] = useState(false);

  const onCopy = useCallback(async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1500);
      }
    } catch {
      /* clipboard unavailable – ignore */
    }
  }, [text]);

  return (
    <div data-testid="safe-payload-example" className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium uppercase tracking-wide text-slate-600">
          Safe payload example (masked values only)
        </p>
        <button
          type="button"
          onClick={onCopy}
          className="rounded border border-slate-300 px-2 py-0.5 text-xs font-medium text-slate-700 hover:bg-slate-100"
        >
          {copied ? "Copied" : "Copy JSON"}
        </button>
      </div>
      <pre className="max-h-72 overflow-auto rounded-md border border-navy-900 bg-navy-900 p-3 font-mono text-xs leading-relaxed text-slate-50">
        {text}
      </pre>
      <p className="text-xs text-slate-500">
        Only masked or safety-validated values are accepted. Raw phone numbers,
        wallet IDs, JWTs, bearer tokens, API keys, passwords, password hashes
        or private keys are rejected by the inbound safety scanner.
      </p>
    </div>
  );
}
