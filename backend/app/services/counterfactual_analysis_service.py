from __future__ import annotations

import hashlib
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.counterfactual_analysis import (
    CounterfactualAnalysis,
    CounterfactualTestResult,
)
from app.models.evidence_file import EvidenceFile
from app.models.root_cause_score import RootCauseScore
from app.schemas.counterfactual_analysis_schema import CounterfactualRunRequest
from app.services import audit_service, causality_engine
from app.services.integrity_ledger_service import canonical_json

MAX_EVIDENCE_ITEMS = 25
RETEST_EVIDENCE_TYPES = causality_engine.RETEST_EVIDENCE_TYPES
COUNTERFACTUAL_METHOD_VERSION = "counterfactual-removal-v2"


class CounterfactualError(Exception):
    pass


class CounterfactualNotFoundError(CounterfactualError):
    pass


class CounterfactualStateError(CounterfactualError):
    pass


def classify_importance(
    *, score_change: float, rank_changed: bool, test_type: str
) -> str:
    if test_type == "contradiction_removal":
        return "contradictory"
    if test_type == "unrelated_removal":
        return "irrelevant"
    if rank_changed:
        return "decisive"
    if score_change >= 0.20:
        return "strong_support"
    if score_change >= 0.05:
        return "weak_support"
    return "redundant"


def classify_stability(
    *, baseline_score: float, supporting_count: int, results: list[dict[str, Any]]
) -> str:
    if baseline_score <= 0 or supporting_count == 0:
        return "insufficient_evidence"
    removals = [
        item
        for item in results
        if item["test_type"] in {"evidence_removal", "duplicate_removal"}
    ]
    if any(item["rank_changed"] or item["score_change"] >= 0.20 for item in removals):
        return "fragile"
    if any(item["score_change"] >= 0.05 for item in removals):
        return "moderately_stable"
    return "stable"


def _ruleset_version(rules: dict) -> str:
    explicit = rules.get("version") or rules.get("ruleset_version")
    if explicit:
        return str(explicit)
    digest = hashlib.sha256(canonical_json(rules).encode("utf-8")).hexdigest()[:16]
    return f"root-cause-rules-sha256:{digest}"


def _ranked_target(
    db: Session,
    incident_id: str,
    cause_name: str,
    rules: dict,
    excluded: set[str] | None = None,
) -> tuple[float, int | None]:
    context = causality_engine.build_evidence_context(
        db,
        incident_id,
        excluded_evidence_ids=excluded,
    )
    ranked = causality_engine.rank_causes(context, rules)
    for rank, item in enumerate(ranked, start=1):
        if item.likely_root_cause == cause_name:
            return item.final_score, rank
    return 0.0, None


def _root_cause(
    db: Session, incident_id: str, root_cause_id: str | None
) -> RootCauseScore:
    if root_cause_id:
        # `root_cause_id` is globally unique, so a historical (superseded)
        # row can still be looked up explicitly by id if a caller has one.
        item = db.scalar(
            select(RootCauseScore).where(
                RootCauseScore.incident_id == incident_id,
                RootCauseScore.root_cause_id == root_cause_id,
            )
        )
    else:
        # Phase N: default to the incident's current analysis version only.
        rows = causality_engine.list_root_cause_scores(db, incident_id)
        item = rows[0] if rows else None
    if item is None:
        raise CounterfactualNotFoundError(
            "No matching root-cause result is available for this incident."
        )
    return item


def _evidence_sets(
    db: Session,
    incident_id: str,
    baseline: Any,
) -> tuple[list[str], list[str], list[str], set[str], list[dict[str, str | None]]]:
    evidence_rows = list(
        db.scalars(
            select(EvidenceFile).where(EvidenceFile.linked_incident_id == incident_id)
        ).all()
    )
    evidence_types = {
        row.evidence_id: (
            row.evidence_type.value
            if hasattr(row.evidence_type, "value")
            else str(row.evidence_type)
        )
        for row in evidence_rows
    }
    hashes: dict[str, list[str]] = {}
    for row in evidence_rows:
        if row.file_hash:
            hashes.setdefault(row.file_hash, []).append(row.evidence_id)
    duplicate_ids = {
        evidence_id
        for group in hashes.values()
        if len(group) > 1
        for evidence_id in group[1:]
    }

    matched = {
        evidence_id
        for signal in baseline.matched_signals
        for evidence_id in signal.get("evidence_ids") or []
        if evidence_id and evidence_id != "unknown"
    }
    contradictory = {
        item.get("evidence_id")
        for item in baseline.contradicting_evidence
        if item.get("evidence_id") and item.get("evidence_id") != "unknown"
    }
    retest = {
        evidence_id
        for evidence_id, evidence_type in evidence_types.items()
        if evidence_type in RETEST_EVIDENCE_TYPES
    } | set(baseline.retest_evidence_ids or [])
    supporting = sorted(matched - contradictory - retest)
    unrelated = sorted(set(evidence_types) - matched - contradictory - retest)
    evidence_state = [
        {
            "evidence_id": row.evidence_id,
            "evidence_type": evidence_types[row.evidence_id],
            "file_hash": row.file_hash,
        }
        for row in sorted(evidence_rows, key=lambda item: item.evidence_id)
    ]
    return supporting, sorted(contradictory), unrelated, duplicate_ids, evidence_state


def select_evidence_for_analysis(
    supporting: list[str],
    contradictory: list[str],
    unrelated: list[str],
    *,
    limit: int,
) -> tuple[list[str], list[str], list[str], list[str]]:
    considered = (supporting + contradictory + unrelated)[:limit]
    selected = set(considered)
    return (
        [item for item in supporting if item in selected],
        [item for item in contradictory if item in selected],
        [item for item in unrelated if item in selected],
        considered,
    )


def counterfactual_fingerprint(
    *,
    incident_id: str,
    root_cause_id: str,
    ruleset_version: str,
    baseline_score: float,
    baseline_rank: int,
    matched_signals: list[dict[str, Any]],
    contradicting_evidence: list[dict[str, Any]],
    considered: list[str],
    evidence_state: list[dict[str, str | None]],
) -> str:
    payload = {
        "method_version": COUNTERFACTUAL_METHOD_VERSION,
        "incident_id": incident_id,
        "root_cause_id": root_cause_id,
        "ruleset_version": ruleset_version,
        "baseline_score": baseline_score,
        "baseline_rank": baseline_rank,
        "matched_signals": matched_signals,
        "contradicting_evidence": contradicting_evidence,
        "evidence_ids": considered,
        "evidence_state": [
            item for item in evidence_state if item["evidence_id"] in considered
        ],
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _result(
    *,
    test_type: str,
    evidence_id: str,
    baseline_score: float,
    baseline_rank: int,
    score_after: float,
    rank_after: int | None,
) -> dict[str, Any]:
    score_change = round(baseline_score - score_after, 4)
    rank_changed = rank_after != baseline_rank
    role = classify_importance(
        score_change=score_change,
        rank_changed=rank_changed,
        test_type=test_type,
    )
    return {
        "test_type": test_type,
        "evidence_id": evidence_id,
        "evidence_role": role,
        "score_before": baseline_score,
        "score_after": round(score_after, 4),
        "score_change": score_change,
        "rank_before": baseline_rank,
        "rank_after": rank_after,
        "rank_changed": rank_changed,
        "importance_level": role,
        "explanation": (
            f"Removing evidence {evidence_id} changed the rule score by "
            f"{score_change:.4f} and produced rank "
            f"{rank_after if rank_after is not None else 'not ranked'}."
        ),
    }


def _get(db: Session, analysis_id: str) -> CounterfactualAnalysis:
    item = db.scalar(
        select(CounterfactualAnalysis)
        .options(selectinload(CounterfactualAnalysis.test_results))
        .where(CounterfactualAnalysis.analysis_id == analysis_id)
    )
    if item is None:
        raise CounterfactualNotFoundError(
            f"Counterfactual analysis not found: {analysis_id}"
        )
    return item


def run_analysis(
    db: Session,
    incident_id: str,
    body: CounterfactualRunRequest,
    *,
    actor_id: int | None,
) -> tuple[CounterfactualAnalysis, bool]:
    root_cause = _root_cause(db, incident_id, body.root_cause_id)
    rules = causality_engine.load_root_cause_rules()
    ruleset_version = _ruleset_version(rules)
    context = causality_engine.build_evidence_context(db, incident_id)
    ranked = causality_engine.rank_causes(context, rules)
    baseline = next(
        (
            (rank, item)
            for rank, item in enumerate(ranked, start=1)
            if item.likely_root_cause == root_cause.likely_root_cause
        ),
        None,
    )
    if baseline is None:
        raise CounterfactualStateError(
            "The stored root cause is not produced by the current rule set."
        )
    baseline_rank, baseline_result = baseline
    baseline_score = baseline_result.final_score
    supporting, contradictory, unrelated, duplicate_ids, evidence_state = _evidence_sets(
        db, incident_id, baseline_result
    )
    limit = min(body.max_evidence_items, MAX_EVIDENCE_ITEMS)
    selected_supporting, selected_contradictory, selected_unrelated, considered = (
        select_evidence_for_analysis(
            supporting,
            contradictory,
            unrelated,
            limit=limit,
        )
    )
    fingerprint = counterfactual_fingerprint(
        incident_id=incident_id,
        root_cause_id=root_cause.root_cause_id,
        ruleset_version=ruleset_version,
        baseline_score=baseline_score,
        baseline_rank=baseline_rank,
        matched_signals=baseline_result.matched_signals,
        contradicting_evidence=baseline_result.contradicting_evidence,
        considered=considered,
        evidence_state=evidence_state,
    )
    existing = db.scalar(
        select(CounterfactualAnalysis)
        .options(selectinload(CounterfactualAnalysis.test_results))
        .where(
            CounterfactualAnalysis.root_cause_id == root_cause.root_cause_id,
            CounterfactualAnalysis.causal_ruleset_version == ruleset_version,
            CounterfactualAnalysis.input_fingerprint == fingerprint,
        )
    )
    if existing is not None:
        return existing, False

    results: list[dict[str, Any]] = []
    for evidence_id in selected_supporting:
        score_after, rank_after = _ranked_target(
            db,
            incident_id,
            root_cause.likely_root_cause,
            rules,
            {evidence_id},
        )
        results.append(
            _result(
                test_type=(
                    "duplicate_removal"
                    if evidence_id in duplicate_ids
                    else "evidence_removal"
                ),
                evidence_id=evidence_id,
                baseline_score=baseline_score,
                baseline_rank=baseline_rank,
                score_after=score_after,
                rank_after=rank_after,
            )
        )
    for test_type, evidence_ids in (
        ("contradiction_removal", selected_contradictory),
        ("unrelated_removal", selected_unrelated),
    ):
        for evidence_id in evidence_ids:
            score_after, rank_after = _ranked_target(
                db,
                incident_id,
                root_cause.likely_root_cause,
                rules,
                {evidence_id},
            )
            results.append(
                _result(
                    test_type=test_type,
                    evidence_id=evidence_id,
                    baseline_score=baseline_score,
                    baseline_rank=baseline_rank,
                    score_after=score_after,
                    rank_after=rank_after,
                )
            )

    stability = classify_stability(
        baseline_score=baseline_score,
        supporting_count=len(selected_supporting),
        results=results,
    )
    minimal_set: list[str] = []
    limitations = [
        "This is rule-based counterfactual analysis and not proof of causation.",
        "Retest and remediation evidence was excluded from original-cause support.",
    ]
    if baseline_rank == 1 and selected_supporting and len(selected_supporting) == len(supporting):
        excluded: set[str] = set()
        ordered = sorted(
            (
                item
                for item in results
                if item["test_type"] in {"evidence_removal", "duplicate_removal"}
            ),
            key=lambda item: (item["score_change"], item["evidence_id"]),
        )
        for item in ordered:
            trial = excluded | {item["evidence_id"]}
            score_after, rank_after = _ranked_target(
                db,
                incident_id,
                root_cause.likely_root_cause,
                rules,
                trial,
            )
            if rank_after == 1 and score_after > 0:
                excluded = trial
        minimal_set = sorted(set(selected_supporting) - excluded)
        limitations.append(
            "The minimal set is a deterministic greedy approximation, not an exhaustive search."
        )
    else:
        limitations.append(
            "A minimal top-ranking evidence set was not calculated because the selected cause was not ranked first or supporting evidence was truncated."
        )
    if len(supporting) > limit:
        limitations.append(
            f"Analysis was limited to {limit} of {len(supporting)} supporting evidence items."
        )

    analysis = CounterfactualAnalysis(
        analysis_id=f"CFA-{uuid.uuid4().hex[:20].upper()}",
        incident_id=incident_id,
        root_cause_id=root_cause.root_cause_id,
        causal_ruleset_version=ruleset_version,
        method_version=COUNTERFACTUAL_METHOD_VERSION,
        input_fingerprint=fingerprint,
        baseline_score=baseline_score,
        baseline_rank=baseline_rank,
        stability_level=stability,
        fragile_conclusion=stability == "fragile",
        minimal_evidence_set=minimal_set,
        missing_evidence_recommendations=list(root_cause.missing_evidence or []),
        limitations=limitations,
        created_by=actor_id,
    )
    db.add(analysis)
    db.flush()
    for item in results:
        db.add(
            CounterfactualTestResult(
                test_result_id=f"CFT-{uuid.uuid4().hex[:20].upper()}",
                analysis_id=analysis.analysis_id,
                **item,
            )
        )
    audit_service.log_action(
        db,
        action="counterfactual_analysis_completed",
        actor_id=actor_id,
        target_type="counterfactual_analysis",
        target_id=analysis.analysis_id,
        details={
            "incident_id": incident_id,
            "root_cause_id": root_cause.root_cause_id,
            "stability_level": stability,
            "tests_run": len(results),
        },
    )
    db.commit()
    return _get(db, analysis.analysis_id), True


def get_analysis(db: Session, analysis_id: str) -> CounterfactualAnalysis:
    return _get(db, analysis_id)


def list_incident_analyses(
    db: Session, incident_id: str
) -> list[CounterfactualAnalysis]:
    return list(
        db.scalars(
            select(CounterfactualAnalysis)
            .options(selectinload(CounterfactualAnalysis.test_results))
            .where(CounterfactualAnalysis.incident_id == incident_id)
            .order_by(CounterfactualAnalysis.created_at.desc())
        ).unique().all()
    )


def list_root_cause_analyses(
    db: Session, root_cause_id: str
) -> list[CounterfactualAnalysis]:
    return list(
        db.scalars(
            select(CounterfactualAnalysis)
            .options(selectinload(CounterfactualAnalysis.test_results))
            .where(CounterfactualAnalysis.root_cause_id == root_cause_id)
            .order_by(CounterfactualAnalysis.created_at.desc())
        ).unique().all()
    )
