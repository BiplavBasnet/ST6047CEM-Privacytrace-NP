"""Loader for the root-cause ontology (`app/rules/root_cause_ontology.yaml`).

The ontology is a small, transparent catalogue of recognised root-cause
*categories* (see brief Section 17), each declaring which structured
exposure-fact combinations (sensitive type + exposure location) are
consistent with it and which `root_cause_rules.yaml` candidate(s) it
reinforces. `causality_engine.py` uses this module to compute a bounded,
auditable boost — never a standalone verdict — for candidate causes whose
category is corroborated by structured exposure facts (Phase L).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache

import yaml

from app.config import resolve_rules_dir

ONTOLOGY_VERSION_FALLBACK = "unknown"


@dataclass(frozen=True)
class OntologyCategory:
    category_id: str
    display_name: str
    applicable_sensitive_types: frozenset[str]
    applicable_exposure_locations: frozenset[str]
    maps_to_root_causes: tuple[str, ...]
    boost_weight: float
    max_applications: int
    reason: str


@dataclass(frozen=True)
class RootCauseOntology:
    version: str
    categories: tuple[OntologyCategory, ...] = field(default_factory=tuple)

    def categories_for_root_cause(self, likely_root_cause: str) -> list[OntologyCategory]:
        return [c for c in self.categories if likely_root_cause in c.maps_to_root_causes]


def _load_raw_ontology() -> dict:
    path = resolve_rules_dir() / "root_cause_ontology.yaml"
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


@lru_cache(maxsize=1)
def _cached_ontology() -> RootCauseOntology:
    raw = _load_raw_ontology()
    categories: list[OntologyCategory] = []
    for entry in raw.get("categories") or []:
        categories.append(
            OntologyCategory(
                category_id=str(entry.get("id")),
                display_name=str(entry.get("display_name") or entry.get("id")),
                applicable_sensitive_types=frozenset(
                    str(t) for t in (entry.get("applicable_sensitive_types") or [])
                ),
                applicable_exposure_locations=frozenset(
                    str(loc) for loc in (entry.get("applicable_exposure_locations") or [])
                ),
                maps_to_root_causes=tuple(entry.get("maps_to_root_causes") or []),
                boost_weight=float(entry.get("boost_weight", 0.0)),
                max_applications=int(entry.get("max_applications", 1)),
                reason=str(entry.get("reason") or "").strip(),
            )
        )
    return RootCauseOntology(
        version=str(raw.get("version") or ONTOLOGY_VERSION_FALLBACK),
        categories=tuple(categories),
    )


def load_ontology(*, force_reload: bool = False) -> RootCauseOntology:
    """Load and cache the root-cause ontology.

    `force_reload=True` clears the cache first (used by tests that need to
    exercise a fresh parse, and safe to call from long-lived processes after
    a rules-file update).
    """
    if force_reload:
        _cached_ontology.cache_clear()
    return _cached_ontology()


def category_matches_fact(
    category: OntologyCategory,
    *,
    sensitive_type: str | None,
    exposure_location: str | None,
) -> bool:
    """True when a single structured exposure fact corroborates `category`.

    Both the sensitive-type family and exposure-location lists on the
    category must be non-empty and the fact must fall in both — an
    ontology category never fires from an empty/unset fact.
    """
    if not category.applicable_sensitive_types or not category.applicable_exposure_locations:
        return False
    if not sensitive_type or not exposure_location:
        return False
    return (
        sensitive_type in category.applicable_sensitive_types
        and exposure_location in category.applicable_exposure_locations
    )
