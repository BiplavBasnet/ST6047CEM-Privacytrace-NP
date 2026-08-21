import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  scannerBridgeApi,
  type ScannerCorrelationResponse,
  type ScannerEvidenceSafeRead,
  type ScannerImportResponse,
  type ScannerPreviewResponse,
} from "../api/scannerBridgeClient";
import Card from "../components/Card";
import CollapsibleSection from "../components/CollapsibleSection";
import CompactSafetyNotice from "../components/CompactSafetyNotice";
import PageHeader from "../components/PageHeader";
import SafeErrorMessage from "../components/SafeErrorMessage";
import ScannerCorrelationPanel from "../components/ScannerCorrelationPanel";
import ScannerEvidenceTable from "../components/ScannerEvidenceTable";
import ScannerImportPanel from "../components/ScannerImportPanel";
import ScannerPreviewPanel from "../components/ScannerPreviewPanel";
import ScannerSafetyRules from "../components/ScannerSafetyRules";
import { LoadingState } from "../components/LoadingError";
import { useAuth } from "../context/AuthContext";
import { sanitizeString } from "../utils/safety";

export default function ScannerBridgePage() {
  const { can } = useAuth();
  const [searchParams] = useSearchParams();
  const defaultIncident = searchParams.get("incident") ?? "INC-SEED-001";

  const canImport = can("scanner_bridge:import");
  const canRead = can("scanner_bridge:read");

  const [incidentId, setIncidentId] = useState(defaultIncident);
  const [preview, setPreview] = useState<ScannerPreviewResponse | null>(null);
  const [importResult, setImportResult] = useState<ScannerImportResponse | null>(null);
  const [evidence, setEvidence] = useState<ScannerEvidenceSafeRead[]>([]);
  const [correlation, setCorrelation] = useState<ScannerCorrelationResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadEvidence = useCallback(async () => {
    if (!canRead) return;
    setLoading(true);
    setError(null);
    try {
      const rows = await scannerBridgeApi.listEvidence({
        linked_incident_id: incidentId.trim() || undefined,
      });
      setEvidence(rows);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load evidence");
    } finally {
      setLoading(false);
    }
  }, [canRead, incidentId]);

  useEffect(() => {
    void loadEvidence();
  }, [loadEvidence]);

  async function handleCorrelate() {
    if (!incidentId.trim()) return;
    setError(null);
    try {
      const result = await scannerBridgeApi.correlate(incidentId.trim());
      setCorrelation(result);
      await loadEvidence();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Correlation failed");
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        breadcrumbs={[{ label: "Dashboard", to: "/" }, { label: "ScannerBridge-NP" }]}
        title="ScannerBridge-NP"
        description="Import masked scanner findings as supporting evidence."
      />
      <CompactSafetyNotice text="Scanner findings are masked supporting evidence only. They do not replace detection, likely-cause ranking, or fix verification." />
      <CollapsibleSection summary="Safety rules and limitations">
        <ScannerSafetyRules />
        <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-navy-900">
          <li>Only masked metadata and payload hashes are stored — never full scanner dumps.</li>
          <li>Causal relevance is advisory; human review is always required.</li>
          <li>Does not auto-close incidents or mutate fix verification status.</li>
          <li>Five adapter formats are supported; unknown shapes are rejected at the boundary.</li>
        </ul>
      </CollapsibleSection>

      <Card title="1. Import external scanner output">
        {!canImport ? (
          <p className="body-muted">
            Your role can view scanner evidence but cannot import. Ask a security analyst or
            DevSecOps engineer to import masked findings.
          </p>
        ) : (
          <>
            <label className="mb-3 block text-sm font-medium text-navy-900">
              Target incident ID
              <input
                className="field-control mt-1 w-full max-w-md"
                value={incidentId}
                onChange={(e) => setIncidentId(e.target.value)}
              />
            </label>
            <ScannerImportPanel
              incidentId={incidentId}
              canImport={canImport}
              onPreview={setPreview}
              onImported={(result) => {
                setImportResult(result);
                void loadEvidence();
              }}
            />
          </>
        )}
      </Card>

      <Card title="2. Preview (safe masked findings)">
        <ScannerPreviewPanel preview={preview} />
      </Card>

      <Card title="3. Imported scanner evidence">
        {loading ? <LoadingState message="Loading scanner evidence…" /> : null}
        {importResult ? (
          <p className="mb-2 text-xs text-ink-muted">
            {sanitizeString(importResult.message)} ({importResult.imported_count} imported)
          </p>
        ) : null}
        <ScannerEvidenceTable records={evidence} />
      </Card>

      <Card title="4. Correlate with incident">
        <p className="mb-2 text-xs text-ink-muted">
          Rank findings as supporting evidence for incident{" "}
          <span className="font-mono text-navy-800">{sanitizeString(incidentId)}</span>.
        </p>
        <button
          type="button"
          className="btn-primary"
          onClick={() => void handleCorrelate()}
          disabled={!canRead || !incidentId.trim()}
        >
          Run correlation
        </button>
        <div className="mt-4">
          <ScannerCorrelationPanel correlation={correlation} />
        </div>
      </Card>

      {error ? <SafeErrorMessage message={error} /> : null}
    </div>
  );
}
