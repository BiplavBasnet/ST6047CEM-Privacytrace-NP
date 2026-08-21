import { useState } from "react";
import { api } from "../../api/client";
import Card from "../../components/Card";
import CopyableId from "../../components/CopyableId";
import EvidenceGraphPanel from "../../components/differentiation/EvidenceGraphPanel";
import RootCauseScoreBreakdown from "../../components/differentiation/RootCauseScoreBreakdown";
import CounterfactualAnalysisPanel from "../../components/incident/CounterfactualAnalysisPanel";
import { SegmentedTabs } from "../../components/ui/primitives";
import { extractMaskedDetectionsFromTrace, sanitizeString } from "../../utils/safety";
import type { IncidentWorkspaceData } from "./types";

export default function IncidentRootCausePage({
  data,
  onRefresh,
  canAnalyse,
}: {
  data: IncidentWorkspaceData;
  onRefresh: () => void;
  canAnalyse: boolean;
}) {
  const root = data.rootStrength;
  const analysisStale = Boolean(
    root.stale || data.workflow.current_root_cause_analysis_stale,
  );
  const staleReason =
    root.stale_reason || data.workflow.blocked_reasons?.[0] || null;
  const topScore = data.incident.root_cause_scores?.[0];
  const detections = extractMaskedDetectionsFromTrace(data.trace?.timeline);
  const timeline = buildTimeline(data);
  const rootStage = data.workflow.stages.find((stage) => stage.code === "root_cause");
  const [analysing, setAnalysing] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [tab, setTab] = useState("summary");

  async function runAnalysis() {
    setAnalysing(true);
    setAnalysisError(null);
    try {
      await api.analyseIncident(data.incident.incident_id);
      onRefresh();
    } catch {
      setAnalysisError("Root-cause analysis could not be completed. Check the linked masked evidence.");
    } finally {
      setAnalysing(false);
    }
  }

  return (
    <>
      {!rootStage?.completed ? (
        <Card title="Root Cause Analysis">
          <p className="text-sm text-navy-900">
            Rank likely causes from the linked masked evidence before review.
          </p>
          <button
            type="button"
            onClick={runAnalysis}
            disabled={analysing || !canAnalyse || rootStage?.available !== true}
            className="btn-primary mt-3"
          >
            {analysing ? "Analysing..." : "Run Root Cause Analysis"}
          </button>
          {!canAnalyse ? (
            <p className="mt-2 text-xs text-ink-subtle">Your role cannot run workflow analysis.</p>
          ) : null}
          {rootStage?.blocked_reason ? (
            <p className="mt-2 text-xs text-amber-800">{sanitizeString(rootStage.blocked_reason)}</p>
          ) : null}
          {analysisError ? <p className="mt-2 text-sm text-red-700">{analysisError}</p> : null}
        </Card>
      ) : null}
      <SegmentedTabs
        tabs={[
          { id: "summary", label: "Summary" },
          { id: "evidence", label: "Evidence" },
          { id: "timeline", label: "Timeline" },
          { id: "technical", label: "Technical" },
        ]}
        value={tab}
        onChange={setTab}
      />
      {tab === "summary" ? (
      <>
      <Card title="Likely Cause">
        {analysisStale ? (
          <div className="mb-4 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-950">
            New evidence has been added since this analysis. Reanalysis is required.
            {staleReason ? (
              <span className="mt-1 block text-xs text-amber-900">{sanitizeString(staleReason)}</span>
            ) : null}
          </div>
        ) : null}
        <div className="grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-3">
          <Item label="Likely cause" value={root.likely_root_cause ?? "Not ranked"} />
          <Item label="Confidence level" value={`${root.confidence_level} (${Math.round(root.confidence_score * 100)}%)`} />
          <Item label="Causal strength" value={
              root.causal_evidence_strength?.causal_strength_level
                ? `${root.causal_evidence_strength.causal_strength_level.replaceAll("_", " ")} (${Math.round((root.causal_evidence_strength.causal_strength_score ?? 0) * 100)}%)`
                : `${root.evidence_strength_level.replaceAll("_", " ")} (${Math.round(root.evidence_strength_score * 100)}%)`
            } />
          <Item
            label="Missing evidence"
            value={root.missing_evidence.length ? root.missing_evidence.slice(0, 2).join("; ") : "None listed"}
          />
          <Item
            label="Post-remediation validation"
            value={
              root.post_remediation_validation?.validation_status
                ? `${root.post_remediation_validation.validation_status.replaceAll("_", " ")}${
                    root.post_remediation_validation.validation_score != null
                      ? ` (${Math.round(root.post_remediation_validation.validation_score * 100)}%)`
                      : ""
                  }`
                : "Not yet available"
            }
          />
          <Item label="Human review" value={root.human_review_required ? "Required" : "Recorded"} />
        </div>
        <p className="mt-4 text-sm text-navy-900">{sanitizeString(root.evidence_strength_reason)}</p>
        <p className="mt-2 rounded-md border border-amber-200 bg-amber-50 p-2 text-xs text-amber-900">
          {sanitizeString(root.confidence_cap_reason)}
        </p>
        <p className="mt-2 text-xs text-ink-subtle">
          Causal strength excludes remediation success and review approval. Likely cause is not a proven cause.
          {root.analysis_version != null ? ` Analysis version ${root.analysis_version}.` : ""}
        </p>
      </Card>
      <Card title="Strongest Supporting Evidence">
        {root.supporting_evidence.length ? (
          <ol className="grid gap-3 lg:grid-cols-2">
            {root.supporting_evidence.slice(0, 5).map((item) => (
              <li key={`${item.evidence_id}-${item.evidence_role}`} className="rounded-md border border-slate-200 p-3 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-medium text-navy-900">{sanitizeString(item.evidence_type.replaceAll("_", " "))}</span>
                  <span className="text-xs font-medium text-ink-subtle">{sanitizeString(item.evidence_role.replaceAll("_", " "))}</span>
                </div>
                <p className="mt-2 text-navy-900">{sanitizeString(item.safe_summary)}</p>
                <p className="mt-1 text-xs text-ink-subtle">{sanitizeString(item.support_reason)}</p>
                <div className="mt-2 flex flex-wrap gap-3 text-xs text-ink-subtle">
                  <CopyableId value={item.evidence_id} />
                  {item.source ? <span>{sanitizeString(item.source)}</span> : null}
                  {item.event_time ? <time>{item.event_time}</time> : null}
                </div>
              </li>
            ))}
          </ol>
        ) : (
          <p className="text-sm text-ink-muted">No supporting evidence is linked.</p>
        )}
      </Card>
      </>
      ) : null}

      {tab === "evidence" ? (
      <>
      <Card title="Evidence table">
        {root.supporting_evidence.length ? (
          <ol className="grid gap-3 lg:grid-cols-2">
            {root.supporting_evidence.slice(0, 5).map((item) => (
              <li key={`${item.evidence_id}-${item.evidence_role}`} className="rounded-md border border-slate-200 p-3 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-medium text-navy-900">{sanitizeString(item.evidence_type.replaceAll("_", " "))}</span>
                  <span className="text-xs font-medium text-ink-subtle">{sanitizeString(item.evidence_role.replaceAll("_", " "))}</span>
                </div>
                <p className="mt-2 text-navy-900">{sanitizeString(item.safe_summary)}</p>
                <p className="mt-1 text-xs text-ink-subtle">{sanitizeString(item.support_reason)}</p>
                <div className="mt-2 flex flex-wrap gap-3 text-xs text-ink-subtle">
                  <CopyableId value={item.evidence_id} />
                  {item.source ? <span>{sanitizeString(item.source)}</span> : null}
                  {item.event_time ? <time>{item.event_time}</time> : null}
                </div>
              </li>
            ))}
          </ol>
        ) : (
          <p className="text-sm text-ink-muted">No supporting evidence is linked.</p>
        )}
      </Card>

      {root.contradicting_evidence.length ? (
        <Card title="Evidence against this cause">
          <ul className="space-y-2 text-sm">
            {root.contradicting_evidence.map((item) => (
              <li key={item.evidence_id} className="rounded-md border border-amber-200 bg-amber-50 p-3">
                <p className="font-medium text-amber-950">{sanitizeString(item.safe_summary)}</p>
                <p className="mt-1 text-xs text-amber-800">{sanitizeString(item.support_reason)}</p>
              </li>
            ))}
          </ul>
        </Card>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Missing evidence">
          {root.missing_evidence.length ? (
            <ul className="list-inside list-disc space-y-1 text-sm text-navy-900">
              {root.missing_evidence.slice(0, 3).map((item) => <li key={item}>{sanitizeString(item)}</li>)}
            </ul>
          ) : (
            <p className="text-sm text-ink-muted">No category-level gap is currently listed.</p>
          )}
        </Card>
        <Card title="Recommended next evidence">
          {root.recommended_next_evidence.length ? (
            <ul className="list-inside list-disc space-y-1 text-sm text-navy-900">
              {root.recommended_next_evidence.slice(0, 3).map((item) => <li key={item}>{sanitizeString(item)}</li>)}
            </ul>
          ) : (
            <p className="text-sm text-ink-muted">Continue to human review.</p>
          )}
        </Card>
      </div>
      </>
      ) : null}

      {tab === "timeline" || tab === "technical" ? (
      <div className="space-y-5" data-testid="root-cause-technical-details">
          {tab === "timeline" ? (
          <section>
            <h3 className="text-sm font-semibold text-navy-900">Causal timeline</h3>
            {timeline.length ? (
              <ol className="mt-2 space-y-2 text-sm">
                {timeline.map((item, index) => (
                  <li key={`${item.time}-${index}`} className="grid gap-1 border-l-2 border-slate-300 pl-3 sm:grid-cols-[11rem_1fr]">
                    <time className="text-xs text-ink-subtle">{item.time}</time>
                    <span className="text-navy-900">{sanitizeString(item.label)}</span>
                  </li>
                ))}
              </ol>
            ) : <p className="mt-2 text-sm text-ink-muted">No timestamped evidence is available.</p>}
          </section>
          ) : null}
          {tab === "technical" ? (
          <>
          <CounterfactualAnalysisPanel incidentId={data.incident.incident_id} rootCauseId={topScore?.root_cause_id} />
          <section>
            <h3 className="text-sm font-semibold text-navy-900">Complete candidate ranking</h3>
            {data.incident.root_cause_scores.length ? (
              <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-navy-900">
                {data.incident.root_cause_scores.map((score) => (
                  <li key={`${score.rank}-${score.likely_root_cause}`}>{sanitizeString(score.likely_root_cause)} ({sanitizeString(score.confidence_band ?? "low")})</li>
                ))}
              </ol>
            ) : <p className="mt-2 text-sm text-ink-muted">No candidate ranking is stored.</p>}
          </section>
          <RootCauseScoreBreakdown breakdown={(topScore?.score_breakdown as Record<string, unknown>[] | undefined) ?? []} />
          <section>
            <h3 className="text-sm font-semibold text-navy-900">Masked detections</h3>
            {detections.length ? (
              <ul className="mt-2 space-y-1 text-sm">
                {detections.map((item, index) => (
                  <li key={String(item.detection_id ?? index)}>{sanitizeString(String(item.sensitive_type ?? "sensitive data"))}: <span className="font-mono">{sanitizeString(String(item.masked_value ?? "[MASKED]"))}</span></li>
                ))}
              </ul>
            ) : <p className="mt-2 text-sm text-ink-muted">No masked detections are available.</p>}
          </section>
          <section>
            <h3 className="text-sm font-semibold text-navy-900">Matched and negative signals</h3>
            <p className="mt-1 text-sm text-ink-muted">Matched: {root.matched_signals.length}; negative: {root.negative_signals.length}; contradiction: {root.contradiction_signals.length}.</p>
          </section>
          <EvidenceGraphPanel graph={data.evidenceGraph ?? undefined} />
          <section>
            <h3 className="text-sm font-semibold text-navy-900">Linked evidence IDs</h3>
            <div className="mt-2 flex flex-wrap gap-2">{data.evidence.map((item) => <CopyableId key={item.evidence_id} value={item.evidence_id} />)}</div>
          </section>
          </>
          ) : null}
        </div>
      ) : null}
    </>
  );
}

function Item({ label, value }: { label: string; value: string }) {
  return <div><p className="text-xs text-ink-subtle">{label}</p><p className="break-words text-navy-900">{sanitizeString(value)}</p></div>;
}

function buildTimeline(data: IncidentWorkspaceData): { time: string; label: string }[] {
  const items: { time: string; label: string }[] = [];
  for (const alert of data.liveAlerts) {
    items.push({ time: alert.first_seen || alert.alert_time, label: `First live alert ${alert.alert_id}.` });
    if (alert.repeat_count > 1) items.push({ time: alert.last_seen, label: `${alert.repeat_count} correlated alert observations.` });
  }
  for (const item of data.rootStrength.supporting_evidence) {
    if (item.event_time && ["timeline", "technical_cause"].includes(item.evidence_role)) {
      items.push({ time: item.event_time, label: `${item.evidence_type.replaceAll("_", " ")} evidence linked.` });
    }
  }
  for (const action of data.remediationActions) items.push({ time: action.updated_at, label: `Remediation action ${action.status.replaceAll("_", " ")}.` });
  for (const verification of data.verifications.slice(0, 1)) items.push({ time: verification.timestamp, label: `Fix verification ${verification.verification_status}.` });
  return items.sort((a, b) => new Date(a.time).getTime() - new Date(b.time).getTime()).slice(0, 12);
}
