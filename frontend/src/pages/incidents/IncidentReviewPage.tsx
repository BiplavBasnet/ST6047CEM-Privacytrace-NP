import Card from "../../components/Card";
import CollapsibleSection from "../../components/CollapsibleSection";
import HumanReviewPanel from "../../components/HumanReviewPanel";
import CustomerNotificationPanel from "../../components/incident/CustomerNotificationPanel";
import StatusBadge from "../../components/StatusBadge";
import { extractMaskedDetectionsFromTrace, sanitizeString } from "../../utils/safety";
import type { IncidentWorkspaceData } from "./types";

export default function IncidentReviewPage({
  data,
  onRefresh,
  canReview,
}: {
  data: IncidentWorkspaceData;
  onRefresh: () => void;
  canReview: boolean;
}) {
  const stage = data.workflow.stages.find((item) => item.code === "human_review");
  const detections = extractMaskedDetectionsFromTrace(data.trace?.timeline);
  if (!stage?.available) {
    return (
      <>
        <Card title="Human Review">
          <p className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
            {stage?.blocked_reason ?? "Complete Likely Cause before human review."}
          </p>
        </Card>
        <CollapsibleSection summary="Customer notification">
          <CustomerNotificationPanel incidentId={data.incident.incident_id} />
        </CollapsibleSection>
      </>
    );
  }
  if (!canReview) {
    return (
      <>
        <Card title="Human Review">
          <p className="text-sm text-ink-muted">Your role cannot submit a review decision.</p>
        </Card>
        <CollapsibleSection summary="Customer notification">
          <CustomerNotificationPanel incidentId={data.incident.incident_id} />
        </CollapsibleSection>
      </>
    );
  }
  return (
    <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,18rem)_minmax(0,1fr)]">
      <aside className="space-y-3 border border-slate-200 bg-white p-3">
        <p className="eyebrow">Likely cause</p>
        <p className="text-sm font-semibold text-navy-900">{sanitizeString(data.rootStrength.likely_root_cause ?? "Not ranked")}</p>
        <p className="text-xs text-ink-muted">Confidence {sanitizeString(data.rootStrength.confidence_level)}</p>
        <p className="text-xs text-ink-muted">
          Supports {data.rootStrength.supporting_evidence.length} · Against {data.rootStrength.contradicting_evidence.length} · Missing {data.rootStrength.missing_evidence.length}
        </p>
      </aside>
      <div className="min-w-0 space-y-4">
        <Card title="Human Review">
          <HumanReviewPanel
            incidentId={data.incident.incident_id}
            topScore={data.incident.root_cause_scores?.[0]}
            rootStrength={data.rootStrength}
            detectionCount={detections.length}
            missingEvidence={data.rootStrength.missing_evidence}
            latestReview={data.reviews[0]}
            onSubmitted={onRefresh}
          />
        </Card>
        <CollapsibleSection summary="Review history and audit details">
          <div className="grid gap-5 lg:grid-cols-2">
            <section>
              <h3 className="text-sm font-semibold text-navy-900">Final review decisions</h3>
              {data.reviews.length ? (
                <ul className="mt-2 space-y-2 text-sm">
                  {data.reviews.map((review) => (
                    <li key={`${review.timestamp}-${review.decision}`} className="rounded-md border border-slate-200 p-3">
                      <StatusBadge value={review.decision} />
                      <p className="mt-2 text-navy-900">{sanitizeString(review.reason ?? review.comment ?? "No reason available")}</p>
                      <time className="mt-1 block text-xs text-ink-subtle">{review.timestamp}</time>
                    </li>
                  ))}
                </ul>
              ) : <p className="mt-2 text-sm text-ink-muted">No final decision is stored.</p>}
            </section>
            <section>
              <h3 className="text-sm font-semibold text-navy-900">Audit events</h3>
              {data.auditLogs.length ? (
                <ul className="mt-2 space-y-1 text-sm text-navy-900">
                  {data.auditLogs.slice(0, 12).map((item) => <li key={item.id}>{item.timestamp}: {sanitizeString(item.action)}</li>)}
                </ul>
              ) : <p className="mt-2 text-sm text-ink-muted">No audit details are available for this role.</p>}
            </section>
          </div>
        </CollapsibleSection>
        <CollapsibleSection summary="Customer notification">
          <CustomerNotificationPanel incidentId={data.incident.incident_id} />
        </CollapsibleSection>
      </div>
    </div>
  );
}
