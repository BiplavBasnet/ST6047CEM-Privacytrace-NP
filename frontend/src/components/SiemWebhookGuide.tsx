import { sanitizeString } from "../utils/safety";
import { getApiBaseUrl } from "../api/client";

/**
 * Static deployment guide for SOC operators wiring up their SIEM
 * webhooks. All strings are sanitized; no tokens are ever displayed.
 */
export default function SiemWebhookGuide({
  endpointPath = "/integrations/events",
}: {
  endpointPath?: string;
}) {
  const base = sanitizeString(getApiBaseUrl());
  const path = sanitizeString(endpointPath);
  return (
    <div className="space-y-3 text-sm text-slate-700">
      <div>
        <p className="text-xs font-medium uppercase tracking-wide text-slate-600">
          Inbound webhook endpoint
        </p>
        <code className="mt-1 block break-all rounded bg-slate-100 px-2 py-1 font-mono text-xs text-slate-900">
          POST {base}
          {path}
        </code>
      </div>
      <ol className="list-decimal space-y-1 pl-5 text-xs">
        <li>
          Generate a service account on PrivacyTrace-NP with role
          <code className="mx-1 rounded bg-slate-100 px-1 font-mono text-xs">security_analyst</code>
          or
          <code className="mx-1 rounded bg-slate-100 px-1 font-mono text-xs">devsecops_engineer</code>.
        </li>
        <li>
          Issue a short-lived JWT via the standard login flow and use it as
          <code className="mx-1 rounded bg-slate-100 px-1 font-mono text-xs">Authorization: Bearer …</code>.
        </li>
        <li>
          Pre-mask any sensitive value (phone, wallet ID, API key, token,
          password) before forwarding. Unmasked payloads are rejected.
        </li>
        <li>
          Use <code className="rounded bg-slate-100 px-1 font-mono text-xs">source_format</code>
          {" "}
          to declare your payload shape:
          <code className="mx-1 rounded bg-slate-100 px-1 font-mono text-xs">privacytrace_json</code>,
          <code className="mx-1 rounded bg-slate-100 px-1 font-mono text-xs">ocsf_json</code>,
          <code className="mx-1 rounded bg-slate-100 px-1 font-mono text-xs">ecs_json</code>,
          <code className="mx-1 rounded bg-slate-100 px-1 font-mono text-xs">splunk_hec_json</code>{" "}
          or
          <code className="mx-1 rounded bg-slate-100 px-1 font-mono text-xs">generic_json</code>.
        </li>
        <li>
          Inspect the response body. <code className="rounded bg-slate-100 px-1 font-mono text-xs">status</code>
          {" "}
          is <code className="rounded bg-slate-100 px-1 font-mono text-xs">accepted</code>
          {" "}
          or <code className="rounded bg-slate-100 px-1 font-mono text-xs">rejected</code>;
          rejections never echo the unsafe input.
        </li>
      </ol>
    </div>
  );
}
