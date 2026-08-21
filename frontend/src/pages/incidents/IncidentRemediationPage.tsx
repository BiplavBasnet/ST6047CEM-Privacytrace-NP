import { useState } from "react";
import Card from "../../components/Card";
import CollapsibleSection from "../../components/CollapsibleSection";
import ProblemSpecificRemediationPanel from "../../components/ProblemSpecificRemediationPanel";
import RemediationActionPanel from "../../components/incident/RemediationActionPanel";
import ContainmentPanel from "../../components/incident/ContainmentPanel";
import PreventiveControlsPanel from "../../components/incident/PreventiveControlsPanel";
import { SegmentedTabs } from "../../components/ui/primitives";
import type { IncidentWorkspaceData } from "./types";

/** Set true only to temporarily re-enable the deprecated multi-suggestion panel. */
const SHOW_LEGACY_AI_REMEDIATION_PANEL = false;

export default function IncidentRemediationPage({
  data,
  onRefresh,
  canReview,
}: {
  data: IncidentWorkspaceData;
  onRefresh: () => void;
  canReview: boolean;
}) {
  const stage = data.workflow.stages.find((item) => item.code === "remediation");
  const available = Boolean(stage?.available && canReview);
  const blockedReason = !canReview
    ? "Your role cannot save remediation actions."
    : stage?.blocked_reason;
  const [tab, setTab] = useState("recommendation");
  return (
    <>
      <p className="text-xs text-ink-muted">AI-assisted recommendation. Advisory only. Human approval required.</p>
      <SegmentedTabs
        tabs={[
          { id: "recommendation", label: "Recommendation" },
          { id: "implementation", label: "Implementation" },
          { id: "alternatives", label: "Alternatives" },
          { id: "provenance", label: "Provenance" },
        ]}
        value={tab}
        onChange={setTab}
      />
      {tab === "recommendation" || tab === "alternatives" ? (
      <Card title="Evidence-grounded primary remediation">
        <ProblemSpecificRemediationPanel
          incidentId={data.incident.incident_id}
          currentDiagnosisId={data.workflow.diagnosis_id}
          currentGenerationMode={data.workflow.diagnosis_generation_mode}
          chainStatus={data.workflow.workflow_chain_status}
          currentDiagnosis={data.currentDiagnosis}
          onChanged={onRefresh}
        />
      </Card>
      ) : null}
      {tab === "recommendation" || tab === "implementation" ? (
      <Card title="Remediation Action">
        <RemediationActionPanel
          incidentId={data.incident.incident_id}
          actions={data.remediationActions}
          available={available}
          blockedReason={blockedReason}
          onSaved={onRefresh}
          canonicalOnly
        />
        <p className="mt-4 text-xs text-ink-subtle">
          PrivacyTrace-NP records human-owned remediation work; it does not change production code.
        </p>
      </Card>
      ) : null}
      {tab === "provenance" ? (
      <CollapsibleSection summary="Containment and preventive controls" defaultOpen>
        <div className="space-y-4">
          <ContainmentPanel incidentId={data.incident.incident_id} />
          <PreventiveControlsPanel incidentId={data.incident.incident_id} rootCauseId={data.incident.root_cause_scores?.[0]?.root_cause_id} />
        </div>
      </CollapsibleSection>
      ) : null}
      {/* Deprecated: legacy multi-suggestion AIRemediationAssistantPanel — prefer ProblemSpecificRemediationPanel. */}
      {SHOW_LEGACY_AI_REMEDIATION_PANEL && stage?.available && canReview ? (
        <Card title="Legacy multi-suggestion AI assistant (deprecated)">
          {/* Lazy import avoided; flag defaults false so panel stays unused. */}
          <p className="text-sm text-ink-subtle">
            Legacy AIRemediationAssistantPanel is deprecated and hidden by default.
          </p>
        </Card>
      ) : null}
    </>
  );
}
