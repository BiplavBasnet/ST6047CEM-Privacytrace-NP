"""Ranked source-localisation scoring — exact location only above threshold."""

from __future__ import annotations

from typing import Any

# fixed weights; upgrade path = YAML policy if scoring needs tuning.
_SOURCE_WEIGHTS = {
    "sast_finding": 0.55,
    "secret_finding": 0.55,
    "scanner_finding": 0.50,
    "cicd_changed_file": 0.45,
}
_EXACT_THRESHOLD = 0.75
_MAJOR_CONTRADICTION_GAP = 0.20


def _line_range(line_number: int | None) -> str | None:
    if line_number is None:
        return None
    return str(line_number)


def _pick_file_path(*candidates: str | None) -> str | None:
    for candidate in candidates:
        if candidate and str(candidate).strip():
            return str(candidate).strip()
    return None


def _relevance(package: dict[str, Any], row: dict[str, Any], path: str) -> float:
    context = " ".join(
        str(package.get(key) or "")
        for key in ("likely_root_cause", "root_cause_category", "affected_service")
    ) + " " + " ".join(str(item) for item in package.get("exposure_locations") or [])
    terms = {
        term
        for term in context.lower().replace("-", "_").split("_")
        if len(term) >= 4
    }
    candidate = " ".join(str(value) for value in [path, *row.values()]).lower()
    matched = sum(1 for term in terms if term in candidate)
    return min(0.35, matched * 0.12)


def _candidate(package: dict[str, Any], row: dict[str, Any], *, path: str, kind: str, **extra: Any) -> dict[str, Any]:
    relevance = _relevance(package, row, path)
    return {
        "file_path": path,
        "source_location_type": kind,
        "score": _SOURCE_WEIGHTS[kind] + relevance,
        "causal_relevance": relevance,
        **extra,
    }


def score_localisation_candidates(package: dict[str, Any]) -> list[dict[str, Any]]:
    """Return ranked candidate locations with scores in [0, 1]."""
    candidates: list[dict[str, Any]] = []

    for row in package.get("sast_findings") or []:
        path = _pick_file_path(row.get("file_path"))
        if not path:
            continue
        candidates.append(
            _candidate(
                package,
                row,
                path=path,
                kind="sast_finding",
                line_range=_line_range(row.get("line_number")),
                evidence_reference=f"sast:{row.get('evidence_id')}",
                repository_reference=None,
                rationale="Causally relevant SAST finding with file path",
            )
        )

    for row in package.get("secret_findings") or []:
        path = _pick_file_path(row.get("file_path"))
        if not path:
            continue
        candidates.append(
            _candidate(
                package,
                row,
                path=path,
                kind="secret_finding",
                line_range=None,
                evidence_reference=f"secret:{row.get('evidence_id')}",
                repository_reference=None,
                rationale="Causally relevant secret finding with file path",
            )
        )

    for row in package.get("scanner_findings") or []:
        path = _pick_file_path(row.get("source_file"))
        if not path:
            continue
        candidates.append(
            _candidate(
                package,
                row,
                path=path,
                kind="scanner_finding",
                line_range=_line_range(row.get("line_number")),
                evidence_reference=f"scanner:{row.get('scanner_evidence_id')}",
                repository_reference=row.get("repository"),
                rationale="Causally relevant scanner finding with source file",
            )
        )

    for row in package.get("deployment_evidence") or []:
        paths = [p for p in (row.get("changed_file_paths_safe") or []) if p]
        if not paths:
            continue
        candidates.append(
            _candidate(
                package,
                row,
                path=str(paths[0]),
                kind="cicd_changed_file",
                line_range=None,
                evidence_reference=f"cicd:{row.get('cicd_evidence_id')}",
                repository_reference=row.get("commit_reference"),
                rationale="Causally relevant CI/CD changed-file evidence",
            )
        )

    # Soft contradiction: multiple distinct top files with close scores.
    by_path: dict[str, float] = {}
    for cand in candidates:
        path = cand["file_path"]
        by_path[path] = max(by_path.get(path, 0.0), float(cand["score"]))

    ranked_paths = sorted(by_path.items(), key=lambda item: item[1], reverse=True)
    major_contradiction = False
    if len(ranked_paths) >= 2:
        top_score, second_score = ranked_paths[0][1], ranked_paths[1][1]
        if abs(top_score - second_score) < _MAJOR_CONTRADICTION_GAP and ranked_paths[0][0] != ranked_paths[1][0]:
            major_contradiction = True

    for cand in candidates:
        cand["major_contradiction"] = major_contradiction
        if major_contradiction:
            cand["score"] = max(0.0, float(cand["score"]) - 0.15)

    candidates.sort(key=lambda c: float(c["score"]), reverse=True)
    return candidates


def select_best_localisation(
    package: dict[str, Any],
    *,
    threshold: float = _EXACT_THRESHOLD,
) -> dict[str, Any]:
    ranked = score_localisation_candidates(package)
    if not ranked:
        return {
            "exact_source_location_known": False,
            "candidates": [],
            "file_path": None,
            "source_location_type": None,
            "line_range": None,
            "repository_reference": None,
            "evidence_references": [],
            "localisation_confidence": "low",
            "score": 0.0,
            "major_contradiction": False,
        }

    top = ranked[0]
    refs = [
        c["evidence_reference"]
        for c in ranked
        if c.get("evidence_reference") and c["file_path"] == top["file_path"]
    ]
    # Uncontradicted SAST/secret/scanner file is established evidence even when
    # relevance bonus cannot reach the numeric threshold (single-source ceiling).
    uncontradicted_file = (
        not bool(top.get("major_contradiction"))
        and top.get("source_location_type") in {"sast_finding", "secret_finding", "scanner_finding"}
        and bool(top.get("file_path"))
        and len({c["file_path"] for c in ranked}) == 1
        and float(top.get("causal_relevance") or 0) > 0
    )
    exact = (
        not bool(top.get("major_contradiction"))
        and (
            float(top["score"]) >= threshold
            or uncontradicted_file
        )
    )
    confidence = "high" if exact and float(top["score"]) >= 0.9 else (
        "medium" if exact else "low"
    )
    return {
        "exact_source_location_known": exact,
        "candidates": ranked,
        "file_path": top["file_path"] if exact else None,
        "source_location_type": top["source_location_type"] if exact else top["source_location_type"],
        "line_range": top["line_range"] if exact else None,
        "repository_reference": top.get("repository_reference") if exact else None,
        "evidence_references": refs,
        "localisation_confidence": confidence,
        "score": float(top["score"]),
        "major_contradiction": bool(top.get("major_contradiction")),
        "top_candidate_file": top["file_path"],
    }
