import { useCallback, useEffect, useState } from "react";
import { incidentGovernanceApi, type BreachDecision, type IntegrityStatus, type ProvenanceSummary } from "../../api/incidentGovernanceClient";
import { useAuth } from "../../context/AuthContext";
import { sanitizeString } from "../../utils/safety";
import Card from "../Card";
import StatusBadge from "../StatusBadge";

export default function IncidentDecisionTraceabilityPanel({ incidentId }: { incidentId: string }) {
  const { can } = useAuth();
  const [decisions, setDecisions] = useState<BreachDecision[]>([]);
  const [provenance, setProvenance] = useState<ProvenanceSummary | null>(null);
  const [integrity, setIntegrity] = useState<IntegrityStatus | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    try {
      const [decisionData, provenanceData, integrityData] = await Promise.all([
        incidentGovernanceApi.listDecisions(incidentId),
        incidentGovernanceApi.listProvenance(incidentId),
        incidentGovernanceApi.getIntegrity(incidentId),
      ]);
      setDecisions(decisionData.decisions);
      setProvenance(provenanceData);
      setIntegrity(integrityData);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Decision traceability could not be loaded.");
    }
  }, [incidentId]);
  useEffect(() => { void load(); }, [load]);
  const verify = async () => {
    setBusy(true);
    try { await incidentGovernanceApi.verifyIntegrity(incidentId); await load(); }
    catch (err) { setError(err instanceof Error ? err.message : "Integrity verification failed."); }
    finally { setBusy(false); }
  };
  const latest = decisions[0];
  return (
    <Card title="Decision & Evidence Traceability">
      {error ? <p className="mb-3 text-sm text-red-700">{sanitizeString(error)}</p> : null}
      <div className="grid gap-5 lg:grid-cols-3">
        <section>
          <h3 className="text-sm font-semibold text-navy-900">Breach decision record</h3>
          {latest ? <div className="mt-2 space-y-2 text-sm"><div className="flex gap-2"><StatusBadge value={latest.status} /><StatusBadge value={latest.breach_determination} /></div><p className="text-navy-900">Version {latest.decision_version}</p><p className="text-ink-muted">Evidence references: {latest.input_evidence_ids.length}</p></div> : <p className="mt-2 text-sm text-ink-muted">No immutable decision record is available.</p>}
        </section>
        <section>
          <h3 className="text-sm font-semibold text-navy-900">Evidence provenance</h3>
          <div className="mt-2 space-y-2 text-sm"><StatusBadge value={provenance?.status ?? "not_yet_verified"} /><p className="text-navy-900">{provenance?.evidence.length ?? 0} evidence records</p><p className="text-ink-muted">{provenance?.relationships.length ?? 0} traceable relationships</p></div>
        </section>
        <section>
          <h3 className="text-sm font-semibold text-navy-900">Integrity chain</h3>
          <div className="mt-2 space-y-2 text-sm"><StatusBadge value={integrity?.status ?? "not_yet_verified"} /><p className="text-navy-900">{integrity?.records.length ?? 0} ledger records</p>{can("integrity:verify") ? <button className="btn-secondary" disabled={busy} onClick={verify}>{busy ? "Verifying..." : "Verify integrity"}</button> : null}</div>
        </section>
      </div>
      <details className="mt-4 border-t border-slate-200 pt-3"><summary className="cursor-pointer text-sm font-semibold text-navy-700">Technical references</summary><p className="mt-2 text-xs text-ink-muted">Decision IDs, evidence IDs, provenance links, and ledger hashes are available here for authorised review; historical pre-ledger records may remain not yet verified.</p></details>
    </Card>
  );
}
