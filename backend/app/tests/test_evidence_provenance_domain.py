from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.services.evidence_provenance_service import (
    build_paths_from_relationships,
    normalize_sha256,
    relationship_has_cycle,
    validate_values,
)


def _edge(source_type, source_id, target_type, target_id, relationship):
    return SimpleNamespace(
        source_entity_type=source_type,
        source_entity_id=source_id,
        target_entity_type=target_type,
        target_entity_id=target_id,
        relationship_type=relationship,
        reason="Synthetic trace relationship.",
    )


def test_cycle_detection_uses_entity_type_and_rejects_real_cycle():
    typed_edges = [
        (("evidence", "1"), ("decision", "1")),
        (("decision", "1"), ("factor", "1")),
    ]
    assert not relationship_has_cycle(typed_edges)
    assert relationship_has_cycle(
        typed_edges,
        (("factor", "1"), ("evidence", "1")),
    )
    assert not relationship_has_cycle(
        [(("evidence", "same"), ("decision", "same"))]
    )


def test_path_building_is_cycle_safe_and_depth_bounded():
    rows = [
        _edge("decision", "BDR-1", "factor", "F-1", "produced_decision"),
        _edge("factor", "F-1", "evidence", "EVD-1", "supports"),
        _edge("evidence", "EVD-1", "decision", "BDR-1", "correlates_with"),
    ]
    paths = build_paths_from_relationships(
        rows,
        entity_type="decision",
        entity_id="BDR-1",
        max_depth=3,
        max_paths=10,
    )
    assert paths
    assert len(paths) <= 10
    assert all(len(path) <= 3 for path in paths)
    for path in paths:
        visited = [(path[0]["from_type"], path[0]["from_id"])]
        visited.extend((step["to_type"], step["to_id"]) for step in path)
        assert len(visited) == len(set(visited))


def test_provenance_validation_detects_hash_and_timestamp_inconsistency():
    now = datetime.now(timezone.utc)
    status, issues = validate_values(
        source_system="synthetic-source",
        source_timestamp=now,
        collection_timestamp=now - timedelta(minutes=1),
        ingestion_timestamp=now,
        parser_name="synthetic-parser",
        parser_version="1",
        content_sha256="a" * 64,
        evidence_file_hash="b" * 64,
        parent_evidence_id=None,
        evidence_id="EVD-1",
    )
    assert status == "invalid"
    assert {"source_after_collection", "content_hash_mismatch"} <= {
        item["code"] for item in issues
    }
    assert normalize_sha256("A" * 64) == f"sha256:{'a' * 64}"
