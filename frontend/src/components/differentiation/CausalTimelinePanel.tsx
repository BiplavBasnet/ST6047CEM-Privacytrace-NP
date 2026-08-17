import Card from "../Card";
import type { CausalTimelineStage } from "../../utils/causalTimeline";
import { sanitizeString } from "../../utils/safety";

export default function CausalTimelinePanel({
  stages,
}: {
  stages: CausalTimelineStage[];
}) {
  return (
    <Card title="Causal investigation timeline">
      <p className="mb-3 text-xs text-slate-500">
        Stages derived from existing API data only. Timestamps shown when recorded;
        otherwise the stage is marked available or not available.
      </p>
      <ol className="relative space-y-4 border-l border-slate-200 pl-4">
        {stages.map((stage) => (
          <li key={stage.id} className="relative">
            <span
              className={`absolute -left-[1.35rem] top-1 h-2.5 w-2.5 rounded-full ${
                stage.availability === "available" ? "bg-emerald-600" : "bg-slate-300"
              }`}
            />
            <p className="text-sm font-medium text-slate-800">
              {sanitizeString(stage.label)}
            </p>
            <p className="text-xs text-slate-600">
              Status:{" "}
              {stage.availability === "available" ? "available" : "not available"}
            </p>
            {stage.timestamp ? (
              <p className="text-xs text-slate-500">{sanitizeString(stage.timestamp)}</p>
            ) : null}
          </li>
        ))}
      </ol>
    </Card>
  );
}
