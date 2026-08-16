"""Supplementary RCA ablation via frozen causality_engine.rank_causes.

Not comparable to held-out HO-051–070 (those used evaluation/heldout/rca_rank.py).
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
sys.path.insert(0, str(BACKEND))

APPLICATION_FREEZE_SHA = "8b22b670a82b61882cb841b10a9f4d364de30bc7"


def _incident():
    return SimpleNamespace(
        affected_service="wallet-service",
        affected_endpoint="/api/v1/wallet/transfer",
    )


def _scanner():
    return SimpleNamespace(
        scanner_evidence_id="SCN-ABL-001",
        linked_evidence_id="EVD-ABL-SCAN",
        service_hint="wallet-service",
        endpoint_hint="/api/v1/wallet/transfer",
    )


def _deploy_event(first_at: datetime):
    from app.models.normalized_event import NormalizedEvent

    return NormalizedEvent(
        event_id="EVT-ABL-DEPLOY",
        evidence_id="EVD-ABL-DEPLOY",
        timestamp=first_at - timedelta(minutes=10),
        source_type="deployment_log",
        service_name="wallet-service",
        endpoint="/api/v1/wallet/transfer",
        event_type="deployment",
        raw_reference=None,
        masked_message="deployment recorded",
    )


def _base_kwargs(first_at: datetime) -> dict:
    return dict(
        incident_id="INC-ABL-SYNTH",
        incident=_incident(),
        sensitive_types={"nepal_phone", "wallet_id"},
        event_types={"request_body_logged"},
        raw_references=["rule:privacytrace.unsafe-request-body-logging"],
        evidence_types_present={"api_log"},
        evidence_ids_by_type={"api_log": ["EVD-ABL-API"]},
        supporting_evidence_ids={"EVD-ABL-API"},
        first_event_at=first_at,
        last_event_at=first_at,
        masked_messages=["wallet transfer logged"],
        events=[],
        scanner_records=[],
        scanner_services=set(),
        scanner_endpoints=set(),
        evidence_type_by_id={"EVD-ABL-API": "api_log"},
    )


def _summarise(ranked) -> dict:
    top = ranked[:3]
    return {
        "top1": top[0].likely_root_cause if top else None,
        "top3": [s.likely_root_cause for s in top],
        "component": getattr(top[0], "component", None) if top else None,
        "top1_score": round(float(top[0].final_score), 6) if top else None,
        "insufficient": (not top) or float(top[0].final_score) <= 0,
    }


def main() -> None:
    from app.services.causality_engine import EvidenceContext, rank_causes

    first_at = datetime(2026, 8, 17, 12, 0, tzinfo=timezone.utc)
    conditions = ("A", "B", "C")
    bases = ("body_log", "redaction_gap", "sink_keyword", "mixed")
    rows = []
    for base in bases:
        for cond in conditions:
            kw = _base_kwargs(first_at)
            if base == "sink_keyword":
                kw["masked_messages"] = ["external log sink forwarder collector"]
                kw["evidence_types_present"] = {"api_log"}
            if cond in {"B", "C"}:
                scanner = _scanner()
                kw["scanner_records"] = [scanner]
                kw["scanner_services"] = {"wallet-service"}
                kw["scanner_endpoints"] = {"/api/v1/wallet/transfer"}
                kw["evidence_types_present"] = set(kw["evidence_types_present"]) | {"scanner_bridge"}
                kw["evidence_ids_by_type"] = {
                    **kw["evidence_ids_by_type"],
                    "scanner_bridge": ["EVD-ABL-SCAN"],
                }
                kw["supporting_evidence_ids"] = set(kw["supporting_evidence_ids"]) | {"EVD-ABL-SCAN"}
            if cond == "C":
                deploy = _deploy_event(first_at)
                kw["events"] = [deploy]
                kw["evidence_type_by_id"] = {
                    **kw["evidence_type_by_id"],
                    "EVD-ABL-DEPLOY": "deployment_log",
                }
                kw["evidence_types_present"] = set(kw["evidence_types_present"]) | {"deployment_log"}
                kw["evidence_ids_by_type"] = {
                    **kw["evidence_ids_by_type"],
                    "deployment_log": ["EVD-ABL-DEPLOY"],
                }
                kw["supporting_evidence_ids"] = set(kw["supporting_evidence_ids"]) | {"EVD-ABL-DEPLOY"}
                if base == "sink_keyword":
                    kw["masked_messages"] = ["external log sink forwarder collector"]
            ctx = EvidenceContext(**kw)
            ranked = rank_causes(ctx)
            summary = _summarise(ranked)
            rows.append({"base": base, "condition": cond, **summary})

    by_cond = {"A": [], "B": [], "C": []}
    for row in rows:
        by_cond[row["condition"]].append(row)

    def rates(items: list[dict]) -> dict:
        n = len(items)
        # Ablation reports rank occupancy, not labelled Top-1 accuracy.
        return {
            "n": n,
            "top1_causes": [i["top1"] for i in items],
            "mean_top1_score": round(sum(i["top1_score"] or 0 for i in items) / n, 6) if n else None,
            "insufficient_count": sum(1 for i in items if i["insufficient"]),
        }

    payload = {
        "ablation_id": "ABL-RCA-20260817-1",
        "application_freeze_sha": APPLICATION_FREEZE_SHA,
        "method": "causality_engine.rank_causes on synthetic EvidenceContext (no DB)",
        "not_comparable_to": "held-out HO-051–070 SIGNAL_TO_CAUSE ranking",
        "conditions": {
            "A": "primary detector/runtime evidence only",
            "B": "A + scanner_records matching service/endpoint",
            "C": "B + deployment_log 10 minutes before first_event_at",
        },
        "case_count": len(rows),
        "cases": rows,
        "condition_summaries": {k: rates(v) for k, v in by_cond.items()},
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    out = HERE / "results.json"
    if out.exists():
        raise SystemExit("Refusing to overwrite existing ablation results")
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    (HERE / "manifest.json").write_text(
        json.dumps(
            {
                "ablation_id": payload["ablation_id"],
                "application_freeze_sha": APPLICATION_FREEZE_SHA,
                "results_sha256": digest,
                "case_count": len(rows),
                "performed": True,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(out)


if __name__ == "__main__":
    main()
