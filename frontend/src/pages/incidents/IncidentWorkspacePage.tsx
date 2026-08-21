import { useEffect, useMemo, useRef, useState } from "react";
import { Navigate, useLocation, useParams } from "react-router-dom";
import { api } from "../../api/client";
import { liveMonitorApi } from "../../api/liveMonitorClient";
import { remediationLifecycleApi } from "../../api/remediationLifecycleClient";
import { aiRemediationApi } from "../../api/aiRemediationClient";
import InvestigationShell from "../../components/incident/InvestigationShell";
import NotFoundState from "../../components/NotFoundState";
import { ErrorState, LoadingState } from "../../components/LoadingError";
import { useAuth } from "../../context/AuthContext";
import type { IncidentWorkspaceData } from "./types";
import IncidentOverviewPage from "./IncidentOverviewPage";
import IncidentRootCausePage from "./IncidentRootCausePage";
import IncidentReviewPage from "./IncidentReviewPage";
import IncidentRemediationPage from "./IncidentRemediationPage";
import IncidentVerificationPage from "./IncidentVerificationPage";
import IncidentReportPage from "./IncidentReportPage";

const STAGE_ALIASES: Record<string, string> = {
  overview: "overview",
  "root-cause": "root-cause",
  "root-cause-traceability": "root-cause",
  traceability: "root-cause",
  "evidence-chain": "root-cause",
  detections: "root-cause",
  review: "review",
  "human-review": "review",
  remediation: "remediation",
  verification: "verification",
  "fix-verification": "verification",
  report: "report",
  "final-report": "report",
  closure: "report",
};

export default function IncidentWorkspacePage() {
  const { incidentId = "", stage } = useParams();
  const location = useLocation();
  const canonicalStage = stage ? STAGE_ALIASES[stage] : undefined;
  const { can } = useAuth();
  const canRef = useRef(can);
  canRef.current = can;
  const [data, setData] = useState<IncidentWorkspaceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    if (!incidentId || !canonicalStage) return;
    let cancelled = false;
    setError(null);
    (async () => {
      try {
        const [incident, workflow, rootStrength, readiness, remediationResult] =
          await Promise.all([
            api.getIncident(incidentId),
            api.getWorkflowState(incidentId),
            api.getRootCauseEvidenceStrength(incidentId),
            api.getReportReadiness(incidentId),
            api.listRemediationActions(incidentId),
          ]);
        if (cancelled) return;
        setData({
          incident,
          workflow,
          rootStrength,
          readiness,
          remediationActions: remediationResult.remediation_actions,
          remediationLifecycle: null,
          currentDiagnosis: null,
          trace: null,
          evidence: [],
          reviews: [],
          auditLogs: [],
          verifications: [],
          reports: [],
          liveAlerts: [],
          evidenceGraph: null,
        });
        setLoading(false);
        const optional = await Promise.allSettled([
          api.getIncidentTrace(incidentId),
          canRef.current("evidence:read") ? api.listEvidence(incidentId) : Promise.resolve([]),
          canRef.current("incident:review_read")
            ? api.listReviews(incidentId)
            : Promise.resolve({ reviews: [], total: 0 }),
          canRef.current("audit:read")
            ? api.listAuditLogs(incidentId)
            : Promise.resolve({ logs: [], total: 0 }),
          api.listFixVerifications(incidentId),
          api.listReports(incidentId),
          liveMonitorApi.listAlerts({ linkedIncidentId: incidentId, limit: 200 }),
          canRef.current("evidence:read") ? api.getIncidentEvidenceGraph(incidentId) : Promise.resolve(null),
          canRef.current("fix:read") ? remediationLifecycleApi.get(incidentId) : Promise.resolve(null),
          canRef.current("ai_remediation:read") ? aiRemediationApi.getCurrentDiagnosis(incidentId) : Promise.resolve(null),
        ]);
        if (cancelled) return;
        const value = <T,>(index: number, fallback: T): T =>
          optional[index].status === "fulfilled"
            ? (optional[index] as PromiseFulfilledResult<T>).value
            : fallback;
        const reviews = value(2, { reviews: [], total: 0 });
        const audit = value(3, { logs: [], total: 0 });
        const fixes = value(4, { verifications: [], total: 0 });
        const reports = value(5, { reports: [], total: 0 });
        const alerts = value(6, { alerts: [], total: 0 });
        const graph = value<Awaited<ReturnType<typeof api.getIncidentEvidenceGraph>> | null>(7, null);
        const remediationLifecycle = value<Awaited<ReturnType<typeof remediationLifecycleApi.get>> | null>(8, null);
        const currentDiagnosis = value<Awaited<ReturnType<typeof aiRemediationApi.getCurrentDiagnosis>> | null>(9, null);
        setData((current) =>
          current && current.incident.incident_id === incident.incident_id
            ? {
                ...current,
                remediationLifecycle,
                currentDiagnosis,
                trace: value(0, null),
                evidence: value(1, []),
                reviews: reviews.reviews,
                auditLogs: audit.logs,
                verifications: fixes.verifications,
                reports: reports.reports,
                liveAlerts: alerts.alerts,
                evidenceGraph: graph
                  ? { nodes: graph.nodes, edges: graph.edges, disclaimer: graph.disclaimer }
                  : null,
              }
            : current,
        );
      } catch (reason) {
        if (!cancelled) {
          setError(reason instanceof Error ? reason.message : "Failed to load incident workspace");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [incidentId, canonicalStage, reloadKey]);

  const source = useMemo(() => {
    if (!data) return "Manual creation";
    const labels: string[] = [];
    if (data.liveAlerts.length || incidentId.startsWith("INC-LIVE-")) labels.push("Live Monitor");
    if (data.evidence.some((item) => item.evidence_type === "scanner_bridge_import")) labels.push("ScannerBridge-NP");
    if (data.evidence.some((item) => ["deployment_log", "semgrep_report", "gitleaks_report", "trivy_report"].includes(item.evidence_type))) labels.push("CI/CD Evidence");
    if (!labels.length && data.evidence.length) labels.push("Evidence Import");
    return labels.length > 1 ? "Mixed Evidence" : labels[0] ?? "Manual creation";
  }, [data, incidentId]);

  if (!stage) {
    const legacyAnchor = location.hash.replace(/^#/, "");
    const legacyStage = STAGE_ALIASES[legacyAnchor] ?? "overview";
    return <Navigate to={`/incidents/${encodeURIComponent(incidentId)}/${legacyStage}`} replace />;
  }
  if (!canonicalStage) return <Navigate to={`/incidents/${encodeURIComponent(incidentId)}/overview`} replace />;

  const isNotFound = !!error && /not found|404/i.test(error);
  const refresh = () => setReloadKey((key) => key + 1);

  return (
    <div className="space-y-4">
      {loading ? <LoadingState message="Loading incident workflow..." /> : null}
      {error && isNotFound ? (
        <NotFoundState title="Incident not found" description="This incident could not be found or you no longer have access." backTo="/incidents" backLabel="Back to Incidents" />
      ) : null}
      {error && !isNotFound ? <ErrorState message={error} /> : null}

      {data ? (
        <InvestigationShell
          incident={data.incident}
          source={source}
          workflow={data.workflow}
          rootStrength={data.rootStrength}
          activeStage={canonicalStage}
        >
          <main data-testid="workflow-stage-panel" data-stage={canonicalStage} className="space-y-4">
            {canonicalStage === "overview" ? <IncidentOverviewPage data={data} source={source} /> : null}
            {canonicalStage === "root-cause" ? (
              <IncidentRootCausePage
                data={data}
                onRefresh={refresh}
                canAnalyse={can("workflow:analyse")}
              />
            ) : null}
            {canonicalStage === "review" ? <IncidentReviewPage data={data} onRefresh={refresh} canReview={can("incident:review")} /> : null}
            {canonicalStage === "remediation" ? <IncidentRemediationPage data={data} onRefresh={refresh} canReview={can("incident:review")} /> : null}
            {canonicalStage === "verification" ? <IncidentVerificationPage data={data} onRefresh={refresh} canVerify={can("fix:verify")} canRetest={can("live_monitor:ingest")} /> : null}
            {canonicalStage === "report" ? <IncidentReportPage data={data} canExport={can("report:generate")} /> : null}
          </main>
        </InvestigationShell>
      ) : null}
    </div>
  );
}
