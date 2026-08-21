export type EvidenceGraphNode = {
  id: string;
  type: string;
  label?: string;
};

export type EvidenceGraphEdge = {
  source: string;
  target: string;
  relationship: string;
};

export type NodePosition = {
  x: number;
  y: number;
  layer: number;
};

export type PositionedEdge = EvidenceGraphEdge & {
  path: string;
  from: NodePosition;
  to: NodePosition;
};

const LAYER_INDEX: Record<string, number> = {
  incident: 0,
  evidence: 1,
  normalized_event: 2,
  detection: 3,
  root_cause: 4,
};

export const NODE_WIDTH = 132;
export const NODE_HEIGHT = 38;
const LAYER_GAP = 168;
const ROW_GAP = 10;
const PAD = 28;

function layerForType(type: string): number {
  return LAYER_INDEX[type] ?? 2;
}

export function layoutEvidenceGraph(
  nodes: EvidenceGraphNode[],
  edges: EvidenceGraphEdge[],
): {
  positions: Map<string, NodePosition>;
  width: number;
  height: number;
  positionedEdges: PositionedEdge[];
  layerCounts: Record<string, number>;
} {
  const layers = new Map<number, EvidenceGraphNode[]>();
  for (const node of nodes) {
    const layer = layerForType(node.type);
    const bucket = layers.get(layer) ?? [];
    bucket.push(node);
    layers.set(layer, bucket);
  }

  for (const bucket of layers.values()) {
    bucket.sort((a, b) => a.id.localeCompare(b.id));
  }

  const positions = new Map<string, NodePosition>();
  let maxRows = 0;
  for (const [layerKey, bucket] of layers.entries()) {
    maxRows = Math.max(maxRows, bucket.length);
    bucket.forEach((node, index) => {
      positions.set(node.id, {
        x: PAD + layerKey * LAYER_GAP,
        y: PAD + index * (NODE_HEIGHT + ROW_GAP),
        layer: layerKey,
      });
    });
  }

  const width = PAD * 2 + 4 * LAYER_GAP + NODE_WIDTH;
  const height = Math.max(PAD * 2 + NODE_HEIGHT, PAD * 2 + maxRows * (NODE_HEIGHT + ROW_GAP));

  const positionedEdges: PositionedEdge[] = [];
  for (const edge of edges) {
    const from = positions.get(edge.source);
    const to = positions.get(edge.target);
    if (!from || !to) {
      continue;
    }
    const fromCy = from.y + NODE_HEIGHT / 2;
    const toCy = to.y + NODE_HEIGHT / 2;
    const exitX = from.layer < to.layer ? from.x + NODE_WIDTH : from.x;
    const enterX = from.layer < to.layer ? to.x : to.x + NODE_WIDTH;
    const midX = (exitX + enterX) / 2;
    const path = `M ${exitX} ${fromCy} C ${midX} ${fromCy}, ${midX} ${toCy}, ${enterX} ${toCy}`;
    positionedEdges.push({ ...edge, path, from, to });
  }

  const layerCounts: Record<string, number> = {};
  for (const node of nodes) {
    const key = node.type || "unknown";
    layerCounts[key] = (layerCounts[key] ?? 0) + 1;
  }

  return { positions, width, height, positionedEdges, layerCounts };
}

export const NODE_TYPE_STYLES: Record<
  string,
  { fill: string; stroke: string; text: string; badge: string }
> = {
  incident: {
    fill: "#eef2ff",
    stroke: "#6366f1",
    text: "#312e81",
    badge: "INC",
  },
  evidence: {
    fill: "#eff6ff",
    stroke: "#3b82f6",
    text: "#1e3a8a",
    badge: "EVD",
  },
  normalized_event: {
    fill: "#ecfeff",
    stroke: "#06b6d4",
    text: "#155e75",
    badge: "EVT",
  },
  detection: {
    fill: "#fffbeb",
    stroke: "#f59e0b",
    text: "#92400e",
    badge: "DET",
  },
  root_cause: {
    fill: "#f5f3ff",
    stroke: "#8b5cf6",
    text: "#5b21b6",
    badge: "RC",
  },
};

export function shortNodeId(id: string, max = 18): string {
  if (id.length <= max) return id;
  return `${id.slice(0, 8)}…${id.slice(-6)}`;
}
