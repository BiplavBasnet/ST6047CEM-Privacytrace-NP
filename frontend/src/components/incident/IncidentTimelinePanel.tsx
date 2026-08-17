import { useEffect, useState } from "react";
import { incidentGovernanceApi, type TimelineEvent } from "../../api/incidentGovernanceClient";
import { sanitizeString } from "../../utils/safety";
import Card from "../Card";
import StatusBadge from "../StatusBadge";

export default function IncidentTimelinePanel({ incidentId }: { incidentId: string }) {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [error, setError] = useState("");
  useEffect(() => { incidentGovernanceApi.getTimeline(incidentId).then((result) => setEvents(result.events)).catch((err) => setError(err instanceof Error ? err.message : "Timeline could not be loaded.")); }, [incidentId]);
  return <Card title="Incident Timeline">{error ? <p className="text-sm text-red-700">{sanitizeString(error)}</p> : events.length ? <ol className="space-y-3">{events.slice(0, 20).map((event) => <li key={event.id} className="border-l-2 border-slate-200 pl-3 text-sm"><div className="flex flex-wrap items-center gap-2"><time className="text-xs text-ink-subtle">{event.event_timestamp}</time><StatusBadge value={event.lifecycle_stage} /><StatusBadge value={event.integrity_status} /></div><p className="mt-1 text-navy-900">{sanitizeString(event.summary)}</p>{event.time_status !== "observed" ? <p className="text-xs text-amber-700">Time status: {event.time_status.replaceAll("_", " ")}</p> : null}</li>)}</ol> : <p className="text-sm text-ink-muted">No lifecycle events are available.</p>}</Card>;
}
