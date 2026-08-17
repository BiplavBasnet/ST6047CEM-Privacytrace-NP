import { useMemo, useState } from "react";

import Card from "../Card";
import { sanitizeString } from "../../utils/safety";
import {
  NODE_HEIGHT,
  NODE_TYPE_STYLES,
  NODE_WIDTH,
  layoutEvidenceGraph,
  shortNodeId,
  type EvidenceGraphEdge,
  type EvidenceGraphNode,
} from "../../utils/evidenceGraphLayout";

const LAYER_LABELS = [
  "Incident",
  "Evidence",
  "Events",
  "Detections",
  "Likely causes",
];

function nodeStyle(type: string) {
  return NODE_TYPE_STYLES[type] ?? NODE_TYPE_STYLES.evidence;
}

export default function EvidenceGraphPanel({
  graph,
}: {
  graph:
    | {
        nodes: Record<string, unknown>[];
        edges: Record<string, unknown>[];
        disclaimer?: string;
      }
    | undefined;
}) {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const nodes = useMemo(
    () =>
      (graph?.nodes ?? []).map(
        (n) =>
          ({
            id: String(n.id ?? ""),
            type: String(n.type ?? "evidence"),
            label: n.label != null ? String(n.label) : undefined,
          }) satisfies EvidenceGraphNode,
      ),
    [graph?.nodes],
  );

  const edges = useMemo(
    () =>
      (graph?.edges ?? []).map(
        (e) =>
          ({
            source: String(e.source ?? ""),
            target: String(e.target ?? ""),
            relationship: String(e.relationship ?? ""),
          }) satisfies EvidenceGraphEdge,
      ),
    [graph?.edges],
  );

  const layout = useMemo(() => layoutEvidenceGraph(nodes, edges), [nodes, edges]);

  const disclaimer =
    graph?.disclaimer?.trim() ||
    "Evidence relationships for investigation support.";

  const highlightedEdges = useMemo(() => {
    if (!selectedId) return new Set<number>();
    const set = new Set<number>();
    layout.positionedEdges.forEach((edge, idx) => {
      if (edge.source === selectedId || edge.target === selectedId) {
        set.add(idx);
      }
    });
    return set;
  }, [layout.positionedEdges, selectedId]);

  if (!nodes.length) {
    return (
      <Card title="Evidence graph">
        <p className="text-sm text-slate-500">
          No graph data yet. Run detect and analyse on this incident to build the
          evidence graph.
        </p>
      </Card>
    );
  }

  return (
    <Card title="Evidence graph">
      <p className="text-xs text-slate-500 mb-3">{disclaimer}</p>

      <div className="mb-3 flex flex-wrap gap-2 text-xs">
        {Object.entries(NODE_TYPE_STYLES).map(([type, style]) => (
          <span
            key={type}
            className="inline-flex items-center gap-1 rounded-full border px-2 py-0.5"
            style={{ borderColor: style.stroke, backgroundColor: style.fill, color: style.text }}
          >
            <span className="font-semibold">{style.badge}</span>
            <span className="text-slate-600">
              {layout.layerCounts[type] ?? 0}
            </span>
          </span>
        ))}
      </div>

      <div
        className="overflow-x-auto rounded-lg border border-slate-200 bg-slate-50/80"
        data-testid="evidence-graph-canvas"
      >
        <svg
          width={layout.width}
          height={layout.height}
          className="min-w-full"
          role="img"
          aria-label="Evidence relationship graph"
        >
          <defs>
            <marker
              id="evidence-graph-arrow"
              markerWidth="8"
              markerHeight="8"
              refX="7"
              refY="4"
              orient="auto"
            >
              <path d="M0,0 L8,4 L0,8 Z" fill="#94a3b8" />
            </marker>
          </defs>

          {LAYER_LABELS.map((label, layerIndex) => (
            <text
              key={label}
              x={28 + layerIndex * 168 + NODE_WIDTH / 2}
              y={16}
              textAnchor="middle"
              className="fill-slate-500 text-xs font-medium uppercase tracking-wide"
            >
              {label}
            </text>
          ))}

          {layout.positionedEdges.map((edge, idx) => {
            const active =
              !selectedId || highlightedEdges.has(idx);
            return (
              <path
                key={`${edge.source}-${edge.relationship}-${edge.target}-${idx}`}
                d={edge.path}
                fill="none"
                stroke={active ? "#64748b" : "#cbd5e1"}
                strokeWidth={active ? 1.5 : 1}
                strokeOpacity={active ? 0.85 : 0.35}
                markerEnd="url(#evidence-graph-arrow)"
              />
            );
          })}

          {nodes.map((node) => {
            const pos = layout.positions.get(node.id);
            if (!pos) return null;
            const style = nodeStyle(node.type);
            const selected = selectedId === node.id;
            const safeId = sanitizeString(node.id);
            return (
              <g
                key={node.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                onClick={() =>
                  setSelectedId((prev) => (prev === node.id ? null : node.id))
                }
                className="cursor-pointer"
                role="button"
                tabIndex={0}
                aria-label={`${node.type} ${safeId}`}
                data-testid={`graph-node-${node.id}`}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    setSelectedId((prev) => (prev === node.id ? null : node.id));
                  }
                }}
              >
                <rect
                  width={NODE_WIDTH}
                  height={NODE_HEIGHT}
                  rx={8}
                  fill={style.fill}
                  stroke={selected ? "#0f172a" : style.stroke}
                  strokeWidth={selected ? 2 : 1.25}
                />
                <text
                  x={8}
                  y={14}
                  className="text-xs font-bold"
                  fill={style.text}
                >
                  {style.badge}
                </text>
                <text
                  x={8}
                  y={28}
                  className="text-xs font-medium"
                  fill="#0f172a"
                >
                  {shortNodeId(safeId)}
                </text>
                <title>{`${node.type}: ${safeId}`}</title>
              </g>
            );
          })}
        </svg>
      </div>

      <p className="mt-2 text-xs text-slate-500">
        Click a node to highlight its connections. Full IDs appear on hover.
      </p>

      <details className="mt-3 group">
        <summary className="cursor-pointer text-xs font-medium text-slate-600 hover:text-slate-800">
          Relationship list ({edges.length})
        </summary>
        <div className="mt-2 max-h-48 overflow-y-auto rounded-md border border-slate-200 bg-white">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-slate-50 text-slate-600">
              <tr>
                <th className="px-2 py-1.5 font-medium">From</th>
                <th className="px-2 py-1.5 font-medium">Link</th>
                <th className="px-2 py-1.5 font-medium">To</th>
              </tr>
            </thead>
            <tbody>
              {edges.map((edge, idx) => {
                const rowActive =
                  !selectedId ||
                  edge.source === selectedId ||
                  edge.target === selectedId;
                return (
                  <tr
                    key={`${edge.source}-${edge.relationship}-${edge.target}-${idx}`}
                    className={rowActive ? "bg-white" : "bg-slate-50/60 text-slate-400"}
                  >
                    <td className="px-2 py-1 font-mono">
                      {sanitizeString(shortNodeId(edge.source))}
                    </td>
                    <td className="px-2 py-1">
                      <span className="rounded bg-slate-100 px-1.5 py-0.5 font-medium text-slate-700">
                        {sanitizeString(edge.relationship)}
                      </span>
                    </td>
                    <td className="px-2 py-1 font-mono">
                      {sanitizeString(shortNodeId(edge.target))}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </details>
    </Card>
  );
}
