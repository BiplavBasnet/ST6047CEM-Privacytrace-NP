from __future__ import annotations

from sqlalchemy.orm import Session

from app.services import causality_engine

_GRAPH_DISCLAIMER = (
    "This graph shows evidence relationships and ranked likely causes for review; "
    "edges describe what supports or correlates with a candidate — never that a "
    "candidate was proved to have caused the incident. Final disposition requires "
    "human review."
)

_NODE_TYPE_ORDER = {
    "incident": 0,
    "evidence": 1,
    "normalized_event": 2,
    "detection": 3,
    "root_cause": 4,
}

# Phase O: structural (non-causal) relationships already produced by the
# original graph builder, mapped onto the typed relationship vocabulary.
# `DETECTED_IN` / `REQUIRES_REVIEW` describe evidence structure, not a causal
# claim, so they get a neutral strength of 1.0 (always fully certain that the
# structural link itself exists).
_STRUCTURAL_RELATIONSHIP_TYPES: dict[str, tuple[str, str, float]] = {
    "has_evidence": ("DETECTED_IN", "Evidence item is linked to this incident.", 1.0),
    "normalized_as": (
        "DETECTED_IN",
        "Evidence was normalized into this event for analysis.",
        1.0,
    ),
    "contains_masked_detection": (
        "DETECTED_IN",
        "A masked detection was extracted from this evidence.",
        1.0,
    ),
    "supported_by": (
        "SUPPORTS_CANDIDATE",
        "Evidence correlates with and supports this likely cause.",
        0.5,
    ),
    "contradicted_by": (
        "CONTRADICTS_CANDIDATE",
        "Evidence contradicts or weakens this likely cause.",
        0.5,
    ),
    "requires_human_review": (
        "REQUIRES_REVIEW",
        "Likely-cause ranking requires human review before any action.",
        1.0,
    ),
}

# Phase O: per-signal relationship classification. A matched
# `root_cause_rules.yaml` signal (or ontology boost) becomes its own typed,
# reasoned edge instead of a generic "supported_by" link.
_TIME_CORRELATION_MATCH_TYPES = {
    "deployment_before_incident_within_minutes": "FIRST_APPEARED_AFTER",
    "access_event_near_incident_minutes": "TEMPORALLY_CORRELATES",
    "old_evidence_outside_time_window": "TEMPORALLY_CORRELATES",
}


def _stub_node(node_id: str) -> dict:
    if node_id.startswith("EVD-"):
        return {
            "id": node_id,
            "type": "evidence",
            "label": "Evidence item",
            "role": "supporting_context",
        }
    if node_id.startswith("EVT-"):
        return {
            "id": node_id,
            "type": "normalized_event",
            "label": "normalized_event",
            "safe_summary": "Normalized investigation event",
        }
    if node_id.startswith("DET-"):
        return {
            "id": node_id,
            "type": "detection",
            "label": "masked_detection",
        }
    return {
        "id": node_id,
        "type": "root_cause",
        "label": "likely_root_cause",
    }


def _ensure_edge_endpoints_have_nodes(nodes: dict[str, dict], edges: list[dict]) -> None:
    for edge in edges:
        for endpoint in (edge.get("source"), edge.get("target")):
            if not endpoint:
                continue
            eid = str(endpoint)
            if eid not in nodes:
                nodes[eid] = _stub_node(eid)


def _sort_nodes(nodes: list[dict]) -> list[dict]:
    return sorted(
        nodes,
        key=lambda n: (
            _NODE_TYPE_ORDER.get(str(n.get("type") or ""), 99),
            str(n.get("id") or ""),
        ),
    )


def _make_edge(
    source: str,
    target: str,
    relationship: str,
    *,
    relationship_type: str,
    strength: float,
    relationship_reason: str,
    correlation_rule_id: str | None = None,
) -> dict:
    """Build one graph edge with the Phase O typed-relationship fields.

    `relationship` is kept for backward compatibility with clients reading
    the pre-Phase-O shape; `relationship_type`/`strength`/`relationship_reason`
    /`correlation_rule_id` are the new, explicit fields. Wording is always
    supports/correlates — never "proved caused by".
    """
    return {
        "source": source,
        "target": target,
        "relationship": relationship,
        "relationship_type": relationship_type,
        "strength": round(max(0.0, min(1.0, strength)), 3),
        "relationship_reason": relationship_reason,
        "correlation_rule_id": correlation_rule_id,
    }


def _structural_edge(source: str, target: str, relationship: str) -> dict:
    rel_type, reason, strength = _STRUCTURAL_RELATIONSHIP_TYPES.get(
        relationship, ("RELATED_TO", "Related evidence item.", 0.4)
    )
    return _make_edge(
        source,
        target,
        relationship,
        relationship_type=rel_type,
        strength=strength,
        relationship_reason=reason,
    )


def _signal_strength(weight: float) -> float:
    """Normalise a `root_cause_rules.yaml` signal weight into a 0..1 strength.

    Weights in that file are small fractions of a 0..1 total score (rarely
    above ~0.35); this keeps the strength value legible ("mostly weak-to-
    moderate individual signals") rather than degenerate.
    """
    return min(1.0, abs(weight) / 0.35) if weight else 0.2


def _causal_edges_for_cause(cause: dict) -> list[dict]:
    """Per-signal SUPPORTS/CONTRADICTS/FIRST_APPEARED_AFTER edges (Phase O).

    Built directly from a ranked cause's `score_breakdown` (every matched
    signal, including ontology-boost entries — see `causality_engine.
    _apply_ontology_boost`), so each edge carries the exact reason and
    signal/category id that produced it.
    """
    cause_id = cause.get("root_cause_id")
    if not cause_id:
        return []
    edges: list[dict] = []
    for item in cause.get("score_breakdown") or []:
        if not item.get("matched"):
            continue
        match_type = str(item.get("match_type") or "")
        signal_name = item.get("signal_name")
        reason = item.get("reason") or "Evidence suggests this signal is relevant."
        weight = float(item.get("weight") or 0)
        strength = _signal_strength(weight)

        if item.get("is_contradiction"):
            rel_type = "CONTRADICTS_CANDIDATE"
        elif match_type in _TIME_CORRELATION_MATCH_TYPES:
            rel_type = _TIME_CORRELATION_MATCH_TYPES[match_type]
        else:
            rel_type = "SUPPORTS_CANDIDATE"

        for evidence_id in item.get("evidence_ids") or []:
            if not evidence_id:
                continue
            edges.append(
                _make_edge(
                    cause_id,
                    str(evidence_id),
                    rel_type.lower(),
                    relationship_type=rel_type,
                    strength=strength,
                    relationship_reason=reason,
                    correlation_rule_id=str(signal_name) if signal_name else None,
                )
            )
    return edges


def build_incident_evidence_graph(db: Session, incident_id: str) -> dict:
    trace = causality_engine.get_incident_trace(db, incident_id)
    nodes: list[dict] = [
        {
            "id": trace["incident_id"],
            "type": "incident",
            "label": f"Incident {trace['incident_id']}",
            "safe_summary": "Incident under review",
        }
    ]
    edges: list[dict] = []

    for entry in trace.get("timeline") or []:
        evidence_id = entry.get("evidence_id")
        event_id = entry.get("event_id")
        if evidence_id:
            nodes.append(
                {
                    "id": evidence_id,
                    "type": "evidence",
                    "label": "Evidence item",
                    "role": "supporting_context",
                }
            )
            edges.append(_structural_edge(trace["incident_id"], evidence_id, "has_evidence"))
        if event_id:
            nodes.append(
                {
                    "id": event_id,
                    "type": "normalized_event",
                    "label": entry.get("event_type") or "normalized_event",
                    "safe_summary": "Normalized investigation event",
                }
            )
            if evidence_id:
                edges.append(_structural_edge(evidence_id, event_id, "normalized_as"))
        for det in entry.get("detections") or []:
            det_id = det.get("detection_id")
            if not det_id:
                continue
            nodes.append(
                {
                    "id": det_id,
                    "type": "detection",
                    "label": det.get("sensitive_type") or "masked_detection",
                    "masked_value": det.get("masked_value"),
                }
            )
            if evidence_id:
                edges.append(
                    _structural_edge(evidence_id, det_id, "contains_masked_detection")
                )

    for cause in trace.get("likely_root_causes") or []:
        cause_id = cause.get("root_cause_id")
        if not cause_id:
            continue
        nodes.append(
            {
                "id": cause_id,
                "type": "root_cause",
                "label": cause.get("likely_root_cause") or "likely_root_cause",
                "confidence_band": cause.get("confidence_band"),
            }
        )
        for eid in cause.get("supporting_evidence_ids") or []:
            eid_str = str(eid)
            if eid_str.startswith("EVD-"):
                nodes.append(
                    {
                        "id": eid_str,
                        "type": "evidence",
                        "label": "Evidence item",
                        "role": "supporting_context",
                    }
                )
                edges.append(_structural_edge(trace["incident_id"], eid_str, "has_evidence"))
            edges.append(_structural_edge(cause_id, eid_str, "supported_by"))
        for item in cause.get("contradicting_evidence") or []:
            if item.get("evidence_id"):
                edges.append(
                    _structural_edge(cause_id, item["evidence_id"], "contradicted_by")
                )
        edges.append(_structural_edge(cause_id, trace["incident_id"], "requires_human_review"))

        # Phase O: richer per-signal edges (SUPPORTS_CANDIDATE /
        # CONTRADICTS_CANDIDATE / DETECTED_IN / FIRST_APPEARED_AFTER / ...)
        # carrying the exact matched-signal reason and rule id.
        edges.extend(_causal_edges_for_cause(cause))

    uniq_nodes: dict[str, dict] = {}
    for node in nodes:
        uniq_nodes[str(node["id"])] = node
    uniq_edges: list[dict] = []
    seen_edges: set[tuple[str, str, str, str | None]] = set()
    for edge in edges:
        key = (
            str(edge["source"]),
            str(edge["target"]),
            str(edge["relationship_type"]),
            str(edge.get("correlation_rule_id") or ""),
        )
        if key in seen_edges:
            continue
        seen_edges.add(key)
        uniq_edges.append(edge)

    _ensure_edge_endpoints_have_nodes(uniq_nodes, uniq_edges)

    return {
        "incident_id": incident_id,
        "nodes": _sort_nodes(list(uniq_nodes.values())),
        "edges": sorted(
            uniq_edges,
            key=lambda e: (
                str(e.get("source") or ""),
                str(e.get("relationship_type") or ""),
                str(e.get("target") or ""),
            ),
        ),
        "disclaimer": _GRAPH_DISCLAIMER,
    }
