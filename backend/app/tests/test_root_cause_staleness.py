"""Phase N — root-cause analysis versioning + staleness.

Pure functions (`apply_staleness_to_rows`, `supersede_rows`,
`next_analysis_version`) are tested directly against in-memory
`RootCauseScore` instances (never flushed to a database). `mark_stale` is
tested against a fake `Session`-like object plus a monkeypatched
`list_root_cause_scores`, so no PostgreSQL is required.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from app.models.root_cause_score import RootCauseScore
from app.services import causality_engine
from app.services.causality_engine import (
    apply_staleness_to_rows,
    generate_analysis_id,
    generate_root_cause_id,
    mark_stale,
    next_analysis_version,
    supersede_rows,
)


def _row(**overrides) -> RootCauseScore:
    base = dict(
        root_cause_id=generate_root_cause_id(),
        incident_id="INC-STALE-1",
        cause_name="unsafe_request_body_logging",
        likely_root_cause="unsafe_request_body_logging",
        confidence=0.7,
        confidence_band="medium",
        rank=1,
        score_breakdown=[],
        matched_signals=[],
        negative_signals=[],
        correlation_reasons=[],
        contradicting_evidence=[],
        context_evidence_ids=[],
        remediation_evidence_ids=[],
        retest_evidence_ids=[],
        evidence_roles=[],
        suggested_actions=[],
        human_review_required=True,
        analysis_id="RCA-ANALYSIS-V1",
        analysis_version=1,
        rules_version="rules:abc",
        evidence_snapshot_hash="hash1",
        stale=False,
        stale_reason=None,
        superseded_by_analysis_id=None,
    )
    base.update(overrides)
    return RootCauseScore(**base)


# ---------------------------------------------------------------------------
# next_analysis_version
# ---------------------------------------------------------------------------


def test_next_analysis_version_starts_at_one_when_no_history():
    assert next_analysis_version([]) == 1


def test_next_analysis_version_increments_from_max_existing():
    rows = [_row(analysis_version=1), _row(analysis_version=2)]
    assert next_analysis_version(rows) == 3


# ---------------------------------------------------------------------------
# apply_staleness_to_rows
# ---------------------------------------------------------------------------


def test_apply_staleness_marks_all_rows_and_returns_changed_count():
    rows = [_row(), _row(rank=2)]
    reason = "New detection evidence was added since the last root-cause analysis."
    changed = apply_staleness_to_rows(rows, reason)
    assert changed == 2
    assert all(row.stale for row in rows)
    assert all(row.stale_reason == reason for row in rows)


def test_apply_staleness_is_idempotent_for_same_reason():
    rows = [_row()]
    reason = "New CI/CD evidence was linked since the last root-cause analysis."
    first = apply_staleness_to_rows(rows, reason)
    second = apply_staleness_to_rows(rows, reason)
    assert first == 1
    assert second == 0


def test_apply_staleness_updates_reason_when_it_changes():
    rows = [_row(stale=True, stale_reason="old reason")]
    changed = apply_staleness_to_rows(rows, "new reason")
    assert changed == 1
    assert rows[0].stale_reason == "new reason"


# ---------------------------------------------------------------------------
# supersede_rows
# ---------------------------------------------------------------------------


def test_supersede_rows_only_touches_latest_version_batch():
    old_version_row = _row(analysis_version=1, analysis_id="RCA-ANALYSIS-V1", stale=True, stale_reason="prior")
    latest_row_a = _row(analysis_version=2, analysis_id="RCA-ANALYSIS-V2", rank=1)
    latest_row_b = _row(analysis_version=2, analysis_id="RCA-ANALYSIS-V2", rank=2)
    rows = [old_version_row, latest_row_a, latest_row_b]

    new_id = generate_analysis_id()
    changed = supersede_rows(rows, new_id)

    assert changed == 2
    assert latest_row_a.superseded_by_analysis_id == new_id
    assert latest_row_a.stale is True
    assert latest_row_b.superseded_by_analysis_id == new_id
    # The older, already-superseded batch is left untouched.
    assert old_version_row.superseded_by_analysis_id is None
    assert old_version_row.stale_reason == "prior"


def test_supersede_rows_empty_list_is_noop():
    assert supersede_rows([], "RCA-ANALYSIS-X") == 0


def test_supersede_rows_skips_rows_already_superseded_by_same_id():
    row = _row(superseded_by_analysis_id="RCA-ANALYSIS-SAME")
    changed = supersede_rows([row], "RCA-ANALYSIS-SAME")
    assert changed == 0


# ---------------------------------------------------------------------------
# mark_stale — DB-facing wrapper, tested with a fake Session (no PostgreSQL).
# ---------------------------------------------------------------------------


def test_mark_stale_returns_zero_when_incident_never_analysed(monkeypatch):
    monkeypatch.setattr(causality_engine, "list_root_cause_scores", lambda db, incident_id: [])
    db = MagicMock()
    changed = mark_stale(db, "INC-NEVER-ANALYSED", "some reason")
    assert changed == 0
    db.add_all.assert_not_called()


def test_mark_stale_flags_current_rows_and_registers_them_for_persistence(monkeypatch):
    rows = [_row(), _row(rank=2)]
    monkeypatch.setattr(causality_engine, "list_root_cause_scores", lambda db, incident_id: rows)
    db = MagicMock()
    reason = "A live privacy alert was linked since the last root-cause analysis."
    changed = mark_stale(db, "INC-STALE-2", reason)
    assert changed == 2
    assert all(row.stale for row in rows)
    db.add_all.assert_called_once_with(rows)


def test_mark_stale_does_not_commit_itself(monkeypatch):
    """`mark_stale` must leave transaction control to the caller."""
    rows = [_row()]
    monkeypatch.setattr(causality_engine, "list_root_cause_scores", lambda db, incident_id: rows)
    db = MagicMock()
    mark_stale(db, "INC-STALE-3", "reason")
    db.commit.assert_not_called()


# ---------------------------------------------------------------------------
# analyse_incident re-analysis creates a new version (via a fake DB session
# would require full ORM query support); instead this test verifies the
# pure composition analyse_incident relies on: a fresh id/version is minted
# and the previous batch's rows are marked superseded before the new batch
# is persisted.
# ---------------------------------------------------------------------------


def test_reanalysis_versioning_composition():
    existing_rows = [_row(analysis_version=1, analysis_id="RCA-ANALYSIS-V1")]
    new_version = next_analysis_version(existing_rows)
    new_analysis_id = generate_analysis_id()
    supersede_rows(existing_rows, new_analysis_id)

    assert new_version == 2
    assert existing_rows[0].stale is True
    assert existing_rows[0].superseded_by_analysis_id == new_analysis_id

    new_row = _row(analysis_version=new_version, analysis_id=new_analysis_id, stale=False, stale_reason=None)
    assert new_row.analysis_version == 2
    assert new_row.stale is False
