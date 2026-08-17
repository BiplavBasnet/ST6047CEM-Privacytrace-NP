import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type IncidentSummary } from "../api/client";
import {
  integrationsApi,
  type IntegrationFormatInfo,
  type IntegrationIncidentExportResponse,
} from "../api/integrationsClient";
import { sanitizeString } from "../utils/safety";
import IntegrationFormatSelector from "./IntegrationFormatSelector";
import SafeErrorMessage from "./SafeErrorMessage";

/**
 * SOC export panel:
 * 1. List incidents.
 * 2. Choose an outbound format.
 * 3. Call `/integrations/incidents/{incident_id}/export?format=…`.
 * 4. Render the preview (already safety-validated server-side, then
 *    sanitized client-side as defence-in-depth).
 *
 * No console.log of the raw API response. Tokens are never displayed.
 */
export default function SocExportPanel({
  outboundFormats,
  canExport,
}: {
  outboundFormats: IntegrationFormatInfo[];
  canExport: boolean;
}) {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [loadingIncidents, setLoadingIncidents] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [incidentId, setIncidentId] = useState<string>("");
  const [format, setFormat] = useState<string>("privacytrace_json");
  const [exporting, setExporting] = useState(false);
  const [result, setResult] =
    useState<IntegrationIncidentExportResponse | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await api.listIncidents();
        if (!cancelled) {
          setIncidents(list);
          if (list.length && !incidentId) {
            setIncidentId(list[0].incident_id);
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load incidents");
        }
      } finally {
        if (!cancelled) setLoadingIncidents(false);
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const formatOptions = useMemo(
    () =>
      outboundFormats.map((fmt) => ({
        id: fmt.format_id,
        title: fmt.title,
        description: fmt.description,
      })),
    [outboundFormats],
  );

  const renderedBody = useMemo(() => {
    if (!result) return "";
    if (typeof result.export_body === "string") {
      return sanitizeString(result.export_body);
    }
    return sanitizeString(JSON.stringify(result.export_body, null, 2));
  }, [result]);

  const onExport = useCallback(async () => {
    if (!incidentId) return;
    setExporting(true);
    setExportError(null);
    setResult(null);
    try {
      const response = await integrationsApi.exportIncident(incidentId, format);
      setResult(response);
    } catch (err) {
      setExportError(
        err instanceof Error ? err.message : "Export failed",
      );
    } finally {
      setExporting(false);
    }
  }, [incidentId, format]);

  const onCopy = useCallback(async () => {
    if (!renderedBody) return;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(renderedBody);
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1500);
      }
    } catch {
      /* ignore */
    }
  }, [renderedBody]);

  if (!canExport) {
    return (
      <SafeErrorMessage
        title="Export is restricted"
        message="Your current role does not have integration:export permission."
        hint="Ask an administrator to grant this permission."
      />
    );
  }

  return (
    <div data-testid="soc-export-panel" className="space-y-3">
      {error ? <SafeErrorMessage title="Failed to load incidents" message={error} /> : null}
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="block text-sm font-medium text-slate-700">
          <span className="block">Incident</span>
          <select
            data-testid="soc-export-incident"
            value={incidentId}
            onChange={(event) => setIncidentId(event.target.value)}
            disabled={loadingIncidents || incidents.length === 0}
            className="mt-1 w-full rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm text-slate-800 focus:border-slate-500 focus:outline-none disabled:cursor-not-allowed disabled:bg-slate-100"
          >
            {incidents.length === 0 ? (
              <option value="">No incidents available</option>
            ) : null}
            {incidents.map((incident) => (
              <option key={incident.incident_id} value={incident.incident_id}>
                {sanitizeString(incident.incident_id)} —{" "}
                {sanitizeString(incident.title)}
              </option>
            ))}
          </select>
        </label>
        <IntegrationFormatSelector
          testId="soc-export-format"
          label="Outbound format"
          formats={formatOptions}
          value={format}
          onChange={setFormat}
        />
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={onExport}
          disabled={!incidentId || exporting}
          className="rounded-lg bg-navy-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-navy-800 disabled:cursor-not-allowed disabled:bg-slate-300 disabled:text-slate-500"
        >
          {exporting ? "Exporting…" : "Export safe SOC summary"}
        </button>
        {result ? (
          <button
            type="button"
            onClick={onCopy}
            className="rounded border border-slate-300 px-2 py-1 text-xs font-medium text-slate-700 hover:bg-slate-100"
          >
            {copied ? "Copied" : "Copy output"}
          </button>
        ) : null}
      </div>

      {exportError ? (
        <SafeErrorMessage title="Export failed" message={exportError} />
      ) : null}

      {result ? (
        <div data-testid="soc-export-preview" className="space-y-2">
          <div className="flex flex-wrap items-center gap-3 text-xs text-slate-600">
            <span>
              Format:{" "}
              <code className="rounded bg-slate-100 px-1 font-mono">
                {sanitizeString(result.format)}
              </code>
            </span>
            <span>
              Content-Type:{" "}
              <code className="rounded bg-slate-100 px-1 font-mono">
                {sanitizeString(result.content_type)}
              </code>
            </span>
            <span>
              Generated at:{" "}
              <code className="rounded bg-slate-100 px-1 font-mono">
                {sanitizeString(result.generated_at)}
              </code>
            </span>
          </div>
          <pre className="max-h-72 overflow-auto rounded-md border border-navy-900 bg-navy-900 p-3 font-mono text-xs leading-relaxed text-slate-50">
            {renderedBody}
          </pre>
          <p className="text-xs text-slate-500">
            Output is safety-validated server-side and re-sanitized on the
            client. Masked values only.
          </p>
        </div>
      ) : null}
    </div>
  );
}
