import { useState } from "react";
import {
  SCANNER_SOURCE_FORMATS,
  scannerBridgeApi,
  type ScannerImportBody,
  type ScannerImportResponse,
  type ScannerPreviewResponse,
} from "../api/scannerBridgeClient";
import { sanitizeString } from "../utils/safety";
import SafeErrorMessage from "./SafeErrorMessage";

const FORMAT_LABELS: Record<string, string> = {
  generic_secret_scanner_json: "Generic secret scanner (JSON)",
  external_secret_scanner_json: "External secret scanner (JSON / NDJSON)",
  gitleaks_json: "Secret scan export (JSON array)",
  semgrep_sarif: "Code scan export (SARIF)",
  semgrep_json: "Code scan export (JSON)",
};

function formatLabel(fmt: string): string {
  return FORMAT_LABELS[fmt] ?? sanitizeString(fmt);
}

interface Props {
  incidentId: string;
  onPreview: (preview: ScannerPreviewResponse) => void;
  onImported: (result: ScannerImportResponse) => void;
  canImport: boolean;
}

export default function ScannerImportPanel({
  incidentId,
  onPreview,
  onImported,
  canImport,
}: Props) {
  const [sourceFormat, setSourceFormat] = useState<string>(SCANNER_SOURCE_FORMATS[0]);
  const [jsonText, setJsonText] = useState('[\n  {\n    "RuleID": "demo",\n    "File": "config/example.env",\n    "StartLine": 1,\n    "Redacted": "pk_****_demo"\n  }\n]');
  const [serviceHint, setServiceHint] = useState("wallet-service");
  const [endpointHint, setEndpointHint] = useState("/api/v1/wallet/transfer");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function buildBody(): ScannerImportBody {
    const payload = JSON.parse(jsonText) as unknown;
    return {
      source_format: sourceFormat,
      payload,
      linked_incident_id: incidentId.trim() || undefined,
      service_hint: serviceHint.trim() || undefined,
      endpoint_hint: endpointHint.trim() || undefined,
      source_system: "scanner_bridge_ui",
    };
  }

  async function handlePreview() {
    setBusy(true);
    setError(null);
    try {
      const preview = await scannerBridgeApi.preview(buildBody());
      onPreview(preview);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Preview failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleImport() {
    setBusy(true);
    setError(null);
    try {
      const result = await scannerBridgeApi.import(buildBody());
      onImported(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Import failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      <label className="block text-sm font-medium text-slate-600">
        Source format
        <select
          className="mt-1 w-full rounded-md border border-slate-300 px-2 py-1.5 text-sm"
          value={sourceFormat}
          onChange={(e) => setSourceFormat(e.target.value)}
          disabled={!canImport}
        >
          {SCANNER_SOURCE_FORMATS.map((fmt) => (
            <option key={fmt} value={fmt}>
              {formatLabel(fmt)}
            </option>
          ))}
        </select>
      </label>
      <label className="block text-sm font-medium text-slate-600">
        Masked scanner JSON payload
        <textarea
          className="mt-1 h-40 w-full rounded-md border border-slate-300 font-mono text-xs"
          value={jsonText}
          onChange={(e) => setJsonText(e.target.value)}
          disabled={!canImport}
          spellCheck={false}
        />
      </label>
      <div className="grid gap-2 sm:grid-cols-2">
        <label className="block text-sm font-medium text-slate-600">
          Linked incident
          <input
            className="mt-1 w-full rounded-md border border-slate-300 px-2 py-1.5 text-sm"
            value={incidentId}
            readOnly
          />
        </label>
        <label className="block text-sm font-medium text-slate-600">
          Service hint
          <input
            className="mt-1 w-full rounded-md border border-slate-300 px-2 py-1.5 text-sm"
            value={serviceHint}
            onChange={(e) => setServiceHint(e.target.value)}
            disabled={!canImport}
          />
        </label>
        <label className="block text-sm font-medium text-slate-600 sm:col-span-2">
          Endpoint hint
          <input
            className="mt-1 w-full rounded-md border border-slate-300 px-2 py-1.5 text-sm"
            value={endpointHint}
            onChange={(e) => setEndpointHint(e.target.value)}
            disabled={!canImport}
          />
        </label>
      </div>
      {error ? <SafeErrorMessage message={error} /> : null}
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          className="rounded-lg bg-navy-700 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-navy-800 disabled:opacity-50"
          onClick={() => void handlePreview()}
          disabled={!canImport || busy}
        >
          Preview import
        </button>
        <button
          type="button"
          className="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm disabled:opacity-50"
          onClick={() => void handleImport()}
          disabled={!canImport || busy}
        >
          Import evidence
        </button>
      </div>
    </div>
  );
}
