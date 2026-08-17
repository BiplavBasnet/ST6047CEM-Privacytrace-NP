import { useCallback, useMemo, useState } from "react";
import { sanitizeString } from "../utils/safety";
import {
  SAFE_PAYLOAD_EXAMPLE,
  type IntegrationEventIngestRequest,
} from "../api/integrationsClient";
import { getApiBaseUrl } from "../api/client";

/**
 * Renders a copyable curl command for the inbound ingestion endpoint.
 * The token is shown as a placeholder (`$PRIVACYTRACE_TOKEN`) – we
 * never echo the real token to the DOM, even though the caller may
 * pass one. The example payload is the same one used by
 * `SafePayloadExample`.
 */
export default function CopyCurlExample({
  endpointPath = "/integrations/events",
  payload = SAFE_PAYLOAD_EXAMPLE,
}: {
  endpointPath?: string;
  payload?: IntegrationEventIngestRequest;
}) {
  const base = getApiBaseUrl();
  const json = useMemo(
    () => sanitizeString(JSON.stringify(payload)),
    [payload],
  );
  const safeBase = sanitizeString(base);
  const safePath = sanitizeString(endpointPath);
  const command = useMemo(
    () =>
      [
        `curl -sS -X POST ${safeBase}${safePath} \\`,
        `  -H "Authorization: Bearer $PRIVACYTRACE_TOKEN" \\`,
        `  -H "Content-Type: application/json" \\`,
        `  -d '${json.replace(/'/g, "'\\''")}'`,
      ].join("\n"),
    [safeBase, safePath, json],
  );

  const [copied, setCopied] = useState(false);
  const onCopy = useCallback(async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(command);
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1500);
      }
    } catch {
      /* clipboard unavailable – ignore */
    }
  }, [command]);

  return (
    <div data-testid="copy-curl-example" className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium uppercase tracking-wide text-slate-600">
          Copyable curl example
        </p>
        <button
          type="button"
          onClick={onCopy}
          className="rounded border border-slate-300 px-2 py-0.5 text-xs font-medium text-slate-700 hover:bg-slate-100"
        >
          {copied ? "Copied" : "Copy curl"}
        </button>
      </div>
      <pre className="overflow-auto rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-xs leading-relaxed text-slate-800">
        {command}
      </pre>
      <p className="text-xs text-slate-500">
        The Bearer token placeholder is intentional – real tokens are never
        displayed in the UI.
      </p>
    </div>
  );
}
