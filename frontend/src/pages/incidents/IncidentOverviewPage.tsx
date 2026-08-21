import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import Card from "../../components/Card";
import StatusBadge from "../../components/StatusBadge";
import IncidentPrivacyResponseTabs from "../../components/incident/IncidentPrivacyResponseTabs";
import IncidentDecisionTraceabilityPanel from "../../components/incident/IncidentDecisionTraceabilityPanel";
import IncidentTimelinePanel from "../../components/incident/IncidentTimelinePanel";
import NepalExposurePanel from "../../components/incident/NepalExposurePanel";
import { SegmentedTabs } from "../../components/ui/primitives";
import { extractMaskedDetectionsFromTrace, sanitizeString } from "../../utils/safety";
import type { IncidentWorkspaceData } from "./types";

export default function IncidentOverviewPage({
  data,
  source,
}: {
  data: IncidentWorkspaceData;
  source: string;
}) {
  const [searchParams] = useSearchParams();
  const [tab, setTab] = useState(() => (searchParams.get("privacy-view") ? "privacy" : "privacy"));
  const detections = extractMaskedDetectionsFromTrace(data.trace?.timeline);
  const sensitiveTypes = Array.from(
    new Set([
      ...detections.map((item) => String(item.sensitive_type ?? "")),
      ...data.liveAlerts.flatMap((alert) => alert.sensitive_types ?? []),
    ].filter(Boolean)),
  );
  return (
    <>
      <Card title="What happened">
        <p className="text-sm text-navy-900">
          {sanitizeString(data.incident.summary ?? "Possible privacy exposure requires review.")}
        </p>
        <dl className="mt-4 grid gap-x-5 gap-y-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
          <Item label="Where" value={data.incident.affected_endpoint ?? data.incident.affected_service ?? "Not available"} />
          <Item label="Service" value={data.incident.affected_service ?? "Not available"} />
          <Item label="Data type" value={sensitiveTypes.join(", ") || "None listed"} />
          <div>
            <p className="text-xs text-ink-subtle">How serious</p>
            <div className="mt-1 flex flex-wrap gap-2">
              <StatusBadge value={data.incident.severity} />
              <StatusBadge value={data.workflow.overall_status} />
            </div>
          </div>
          <Item label="Source" value={source} />
          <Item label="First seen" value={data.incident.first_seen ?? "Not available"} />
        </dl>
      </Card>
      <SegmentedTabs
        tabs={[
          { id: "privacy", label: "Privacy response" },
          { id: "timeline", label: "Timeline" },
          { id: "taxonomy", label: "Exposure" },
          { id: "traceability", label: "Traceability" },
        ]}
        value={tab}
        onChange={setTab}
      />
      <div className="mt-3 space-y-4">
        {tab === "privacy" ? <IncidentPrivacyResponseTabs incidentId={data.incident.incident_id} /> : null}
        {tab === "timeline" ? <IncidentTimelinePanel incidentId={data.incident.incident_id} /> : null}
        {tab === "taxonomy" ? <NepalExposurePanel incidentId={data.incident.incident_id} /> : null}
        {tab === "traceability" ? <IncidentDecisionTraceabilityPanel incidentId={data.incident.incident_id} /> : null}
      </div>
    </>
  );
}

function Item({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs text-ink-subtle">{label}</p>
      <p className="break-words text-navy-900">{sanitizeString(value)}</p>
    </div>
  );
}
