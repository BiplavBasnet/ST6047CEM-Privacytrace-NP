import type {
  IncidentDetail,
  IncidentWorkflowState,
  RemediationAction,
  RootCauseEvidenceStrength,
} from "../../api/client";
import { sanitizeString } from "../../utils/safety";
import CopyableId from "../CopyableId";
import StatusBadge from "../StatusBadge";

export default function IncidentSummaryHeader({
  incident,
  source,
  rootStrength: _rootStrength,
  workflow,
  remediationActions: _remediationActions,
}: {
  incident: IncidentDetail;
  source: string;
  rootStrength: RootCauseEvidenceStrength | null;
  workflow: IncidentWorkflowState;
  remediationActions: RemediationAction[];
}) {
  return (
    <section className="sticky top-14 z-20 border-b border-slate-200 bg-white px-1 py-2" aria-label="Incident summary">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <h2 className="text-base font-semibold tracking-tight text-navy-900">
          {sanitizeString(incident.title)}
        </h2>
        <CopyableId value={incident.incident_id} />
        <StatusBadge value={incident.severity} />
        <StatusBadge value={workflow.overall_status} />
        <span className="text-sm text-ink-muted">
          {sanitizeString(incident.affected_service ?? "Service not listed")}
        </span>
        <span className="text-xs text-ink-subtle">{sanitizeString(source)}</span>
      </div>
    </section>
  );
}
