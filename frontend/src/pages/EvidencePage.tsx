import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type EvidenceFile } from "../api/client";
import Card from "../components/Card";
import CollapsibleSection from "../components/CollapsibleSection";
import PageHeader from "../components/PageHeader";
import { ErrorState, LoadingState } from "../components/LoadingError";
import { evidenceMetadataOnly, sanitizeString } from "../utils/safety";
import { userFacingLabel } from "../utils/userFacing";

type ImportKind = "historical" | "supporting" | "retest" | "demo" | "cicd";

const DEFAULT_TYPE: Record<ImportKind, string> = {
  historical: "api_log",
  supporting: "access_event",
  retest: "fixed_log",
  demo: "api_log",
  cicd: "deployment_log",
};

function kindFromType(type: string | null): ImportKind {
  if (!type) return "historical";
  if (type.startsWith("fixed_")) return "retest";
  if (["deployment_log", "semgrep_report", "gitleaks_report", "trivy_report"].includes(type)) {
    return "cicd";
  }
  if (["access_event", "scanner_bridge_import", "siem_alert"].includes(type)) {
    return "supporting";
  }
  return "historical";
}

export default function EvidencePage() {
  const [searchParams] = useSearchParams();
  const requestedType = searchParams.get("type");
  const initialKind = kindFromType(requestedType);
  const [items, setItems] = useState<EvidenceFile[]>([]);
  const [selected, setSelected] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [file, setFile] = useState<File | null>(null);
  const [importKind, setImportKind] = useState<ImportKind>(initialKind);
  const [evidenceType, setEvidenceType] = useState(
    requestedType || DEFAULT_TYPE[initialKind],
  );
  const [sourceSystem, setSourceSystem] = useState("");
  const [linkedIncidentId, setLinkedIncidentId] = useState(
    searchParams.get("incident") || "",
  );
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [validated, setValidated] = useState(false);

  const loadEvidence = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setItems(await api.listEvidence());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load evidence");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadEvidence();
  }, [loadEvidence]);

  function changeKind(value: ImportKind) {
    setImportKind(value);
    setEvidenceType(DEFAULT_TYPE[value]);
    setFile(null);
    setValidated(false);
    setNotice(null);
  }

  async function importEvidence(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      if (importKind === "demo") {
        await api.loadSampleEvidence("scenario_1");
        setNotice("Synthetic demo evidence imported.");
      } else {
        if (!file) {
          setError("Choose a .txt, .log, .json or .csv evidence file.");
          return;
        }
        const result = await api.uploadEvidence({
          file,
          evidenceType,
          sourceSystem,
          linkedIncidentId,
        });
        setNotice(
          `${sanitizeString(result.evidence.evidence_id)} imported as ${sanitizeString(evidenceType)}.`,
        );
        setFile(null);
        setValidated(false);
      }
      await loadEvidence();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to import evidence");
    } finally {
      setBusy(false);
    }
  }

  async function openDetail(evidenceId: string) {
    try {
      const row = await api.getEvidence(evidenceId);
      setSelected(evidenceMetadataOnly(row as unknown as Record<string, unknown>));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load evidence detail");
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        breadcrumbs={[{ label: "Dashboard", to: "/" }, { label: "Evidence Import" }]}
        title="Evidence Import"
        description="Import historical investigation evidence or a controlled retest."
      />

      <Card title="Import Evidence">
        <p className="mb-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-ink-muted">
          {importKind === "retest"
            ? "Controlled retest evidence is used to verify a fix. It is not historical investigation evidence."
            : importKind === "historical"
              ? "Historical evidence supports investigation. It is not a controlled retest."
              : "Choose the purpose before import so historical investigation and controlled retest stay distinct."}
        </p>
        <ol className="mb-4 flex flex-wrap gap-1 text-[11px] font-medium" aria-label="Import sequence">
          {(["Upload", "Validate", "Preview", "Import", "Result"] as const).map((step, index) => {
            const current =
              notice ? "Result"
              : busy ? "Import"
              : validated || importKind === "demo" ? "Preview"
              : file ? "Validate"
              : "Upload";
            const reached = ["Upload", "Validate", "Preview", "Import", "Result"].indexOf(current) >= index;
            return (
              <li key={step} className="flex items-center gap-1">
                <span className={`rounded-md border px-2 py-1 ${reached ? "border-navy-700 bg-navy-800 text-white" : "border-slate-200 text-ink-muted"}`}>
                  {step}
                </span>
                {index < 4 ? <span className="text-ink-subtle" aria-hidden="true">→</span> : null}
              </li>
            );
          })}
        </ol>
        <form onSubmit={importEvidence} className="space-y-4">
          <div className="grid gap-3 md:grid-cols-3">
            <label className="text-sm text-navy-900">
              Evidence purpose
              <select
                aria-label="Evidence purpose"
                value={importKind}
                onChange={(event) => changeKind(event.target.value as ImportKind)}
                className="field-control mt-1 block w-full"
              >
                <option value="historical">Historical log</option>
                <option value="supporting">Supporting evidence</option>
                <option value="retest">Retest evidence</option>
                <option value="demo">Demo evidence</option>
                <option value="cicd">CI/CD evidence</option>
              </select>
            </label>
            {importKind !== "demo" ? (
              <>
                <label className="text-sm text-navy-900 md:col-span-2">
                  Evidence file
                  <input
                    id="evidence-file"
                    type="file"
                    accept=".txt,.log,.json,.csv"
                    onChange={(event) => {
                      setFile(event.target.files?.[0] ?? null);
                      setValidated(false);
                      setNotice(null);
                    }}
                    className="field-control mt-1 block w-full"
                  />
                </label>
                <label className="text-sm text-navy-900">
                  Source system
                  <input
                    value={sourceSystem}
                    onChange={(event) => setSourceSystem(event.target.value)}
                    placeholder="wallet-service"
                    className="field-control mt-1 block w-full"
                  />
                </label>
                <label className="text-sm text-navy-900 md:col-span-2">
                  Incident ID (optional)
                  <input
                    value={linkedIncidentId}
                    onChange={(event) => setLinkedIncidentId(event.target.value)}
                    placeholder="INC-..."
                    className="field-control mt-1 block w-full"
                  />
                </label>
              </>
            ) : (
              <p className="self-end text-sm text-ink-muted md:col-span-2">
                Loads the controlled synthetic thesis scenario.
              </p>
            )}
          </div>

          {importKind !== "demo" ? (
            <CollapsibleSection testId="advanced-evidence-type" summary="Advanced evidence type">
              <label className="block max-w-sm text-sm text-navy-900">
                Parser type
                <select
                  value={evidenceType}
                  onChange={(event) => setEvidenceType(event.target.value)}
                  className="field-control mt-1 block w-full"
                >
                  <option value="api_log">API log</option>
                  <option value="runtime_log">Runtime log</option>
                  <option value="siem_alert">Alert export</option>
                  <option value="access_event">Access event</option>
                  <option value="deployment_log">CI/CD deployment</option>
                  <option value="semgrep_report">Semgrep report</option>
                  <option value="gitleaks_report">Gitleaks report</option>
                  <option value="trivy_report">Trivy report</option>
                  <option value="scanner_bridge_import">ScannerBridge import</option>
                  <option value="fixed_log">Retest fixed log</option>
                  <option value="fixed_scan">Retest fixed scan</option>
                </select>
              </label>
            </CollapsibleSection>
          ) : null}

          {importKind !== "demo" && file && !validated ? (
            <button
              type="button"
              className="btn-secondary"
              onClick={() => {
                const ok = /\.(txt|log|json|csv)$/i.test(file.name);
                if (!ok) {
                  setError("Choose a .txt, .log, .json or .csv evidence file.");
                  return;
                }
                setError(null);
                setValidated(true);
              }}
            >
              Validate file
            </button>
          ) : null}
          {importKind !== "demo" && validated && file ? (
            <p className="text-sm text-navy-900">Preview: {sanitizeString(file.name)} ({Math.round(file.size / 1024)} KB)</p>
          ) : null}
          <button
            type="submit"
            disabled={busy || (importKind !== "demo" && (!file || !validated))}
            className="btn-primary"
          >
            {busy ? "Importing..." : "Import Evidence"}
          </button>
        </form>
      </Card>

      {notice ? (
        <p className="rounded-md bg-emerald-50 px-3 py-2 text-sm text-emerald-900">{notice}</p>
      ) : null}

      <Card title="Evidence list">
        {loading ? <LoadingState /> : null}
        {error ? <ErrorState message={error} /> : null}
        {!loading && !error ? (
          <div className="-mx-5 -mb-5 overflow-x-auto sm:-mx-6">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Evidence ID</th>
                  <th>Type</th>
                  <th>Source</th>
                  <th>Parsing</th>
                  <th>Incident</th>
                </tr>
              </thead>
              <tbody>
                {items.map((row) => (
                  <tr
                    key={row.evidence_id}
                    className="cursor-pointer"
                    onClick={() => void openDetail(row.evidence_id)}
                  >
                    <td className="mono-id text-accent">{row.evidence_id}</td>
                    <td>{userFacingLabel(row.evidence_type)}</td>
                    <td>{sanitizeString(row.source_system ?? "-")}</td>
                    <td>{sanitizeString(row.parsing_status)}</td>
                    <td>{row.linked_incident_id ?? "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        {selected ? (
          <div className="mt-4">
            <CollapsibleSection testId="evidence-metadata" summary="Selected evidence metadata">
              <dl className="grid gap-2 text-sm sm:grid-cols-2">
                {Object.entries(selected).map(([key, value]) => (
                  <div key={key}>
                    <dt className="text-xs text-ink-subtle">{key}</dt>
                    <dd className="font-medium text-navy-900">
                      {sanitizeString(String(value ?? "-"))}
                    </dd>
                  </div>
                ))}
              </dl>
            </CollapsibleSection>
          </div>
        ) : null}
      </Card>
    </div>
  );
}
