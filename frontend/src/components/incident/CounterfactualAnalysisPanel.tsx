import { useCallback, useEffect, useState } from "react";
import { incidentGovernanceApi, type CounterfactualAnalysis } from "../../api/incidentGovernanceClient";
import { useAuth } from "../../context/AuthContext";
import { sanitizeString } from "../../utils/safety";
import CollapsibleSection from "../CollapsibleSection";
import StatusBadge from "../StatusBadge";

export default function CounterfactualAnalysisPanel({ incidentId, rootCauseId }: { incidentId: string; rootCauseId?: string }) {
  const { can } = useAuth();
  const [items, setItems] = useState<CounterfactualAnalysis[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => { try { setItems((await incidentGovernanceApi.listCounterfactual(incidentId)).analyses); setError(""); } catch (err) { setError(err instanceof Error ? err.message : "Counterfactual analysis could not be loaded."); } }, [incidentId]);
  useEffect(() => { void load(); }, [load]);
  const run = async () => { setBusy(true); try { await incidentGovernanceApi.runCounterfactual(incidentId, rootCauseId); await load(); } catch (err) { setError(err instanceof Error ? err.message : "Counterfactual analysis failed."); } finally { setBusy(false); } };
  const latest = items[0];
  return <CollapsibleSection summary="Counterfactual stability analysis"><div className="text-sm">{error ? <p className="mb-3 text-red-700">{sanitizeString(error)}</p> : null}{latest ? <><div className="flex flex-wrap gap-2"><StatusBadge value={latest.stability_level} />{latest.fragile_conclusion ? <StatusBadge value="fragile conclusion" /> : null}</div><p className="mt-2 text-navy-900">Tests whether the likely-cause ranking changes when supporting evidence is removed.</p><p className="mt-2 text-ink-muted">Minimal evidence set: {latest.minimal_evidence_set.join(", ") || "Not established"}</p>{latest.missing_evidence_recommendations.length ? <p className="mt-1 text-ink-muted">Missing evidence: {latest.missing_evidence_recommendations.join("; ")}</p> : null}</> : <p className="text-ink-muted">No counterfactual analysis is recorded.</p>}{can("counterfactual:run") ? <button className="btn-secondary mt-3" disabled={busy || !rootCauseId} onClick={run}>{busy ? "Analysing..." : "Run stability analysis"}</button> : null}<p className="mt-3 text-xs text-ink-subtle">Rule-based stability analysis supports human review and is not proof of causation.</p></div></CollapsibleSection>;
}
