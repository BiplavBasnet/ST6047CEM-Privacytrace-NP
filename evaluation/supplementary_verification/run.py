"""Seal, run once, then score supplementary verification. GT is not loaded during run."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
sys.path.insert(0, str(BACKEND))

APPLICATION_FREEZE_SHA = "8b22b670a82b61882cb841b10a9f4d364de30bc7"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _harness_sha() -> str:
    h = hashlib.sha256()
    for name in ("run.py", "README.md", "inputs.yaml", "ground_truth.yaml"):
        p = HERE / name
        if p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()


def _dump(path: Path, obj: Any) -> None:
    path.write_text(yaml.safe_dump(obj, sort_keys=False, allow_unicode=True), encoding="utf-8")


def seal() -> None:
    if (HERE / "inputs.yaml").exists() or (HERE / "ground_truth.yaml").exists():
        raise SystemExit("Refusing to overwrite sealed supplementary files.")

    inputs: list[dict[str, Any]] = []
    truth: list[dict[str, Any]] = []

    for i in range(1, 5):
        cid = f"SV-{i:03d}"
        inputs.append({
            "case_id": cid,
            "family": "fix_verification_pass",
            "dimensions_match": True,
            "raw_exposure_after_change": False,
        })
        truth.append({"case_id": cid, "family": "fix_verification_pass", "expected_status": "passed"})

    for i in range(5, 9):
        cid = f"SV-{i:03d}"
        inputs.append({
            "case_id": cid,
            "family": "fix_verification_fail",
            "dimensions_match": True,
            "raw_exposure_after_change": True,
        })
        truth.append({"case_id": cid, "family": "fix_verification_fail", "expected_status": "failed"})

    inconclusives = [
        {"dimensions_match": True, "raw_exposure_after_change": None},
        {"dimensions_match": False, "raw_exposure_after_change": False},
        {"dimensions_match": False, "raw_exposure_after_change": True},
        {"dimensions_match": False, "raw_exposure_after_change": None},
    ]
    for offset, payload in enumerate(inconclusives, start=9):
        cid = f"SV-{offset:03d}"
        inputs.append({"case_id": cid, "family": "fix_verification_inconclusive", **payload})
        truth.append({
            "case_id": cid,
            "family": "fix_verification_inconclusive",
            "expected_status": "inconclusive",
        })

    for i in range(13, 16):
        cid = f"SV-{i:03d}"
        inputs.append({
            "case_id": cid,
            "family": "mismatched_retest",
            "dimensions_match": False,
            "raw_exposure_after_change": True,
        })
        truth.append({
            "case_id": cid,
            "family": "mismatched_retest",
            "expected_status": "inconclusive",
        })

    inputs.append({
        "case_id": "SV-016",
        "family": "insufficient_rca",
        "mode": "classify_stability",
        "baseline_score": 0.0,
        "supporting_count": 0,
        "results": [],
    })
    truth.append({
        "case_id": "SV-016",
        "family": "insufficient_rca",
        "expected_stability": "insufficient_evidence",
    })
    inputs.append({
        "case_id": "SV-017",
        "family": "insufficient_rca",
        "mode": "classify_stability",
        "baseline_score": 0.4,
        "supporting_count": 0,
        "results": [],
    })
    truth.append({
        "case_id": "SV-017",
        "family": "insufficient_rca",
        "expected_stability": "insufficient_evidence",
    })
    inputs.append({
        "case_id": "SV-018",
        "family": "insufficient_rca",
        "mode": "causal_strength",
        "incident": {"affected_service": None, "affected_endpoint": None, "first_seen": None},
    })
    truth.append({
        "case_id": "SV-018",
        "family": "insufficient_rca",
        "expected_strength": "weak",
    })

    inputs.append({"case_id": "SV-019", "family": "stale_chain", "mode": "stale", "reason": "New evidence arrived after analysis."})
    truth.append({"case_id": "SV-019", "family": "stale_chain", "expected_stale": True, "expected_changed": 1})
    inputs.append({"case_id": "SV-020", "family": "stale_chain", "mode": "supersede", "new_analysis_id": "RCA-ANALYSIS-SUPP020"})
    truth.append({"case_id": "SV-020", "family": "stale_chain", "expected_superseded": True, "expected_changed": 1})

    inputs.append({
        "case_id": "SV-021",
        "family": "verified_learning",
        "diagnosis_status": "accepted",
        "verification_status": "passed",
    })
    truth.append({"case_id": "SV-021", "family": "verified_learning", "expected_eligible": True})
    inputs.append({
        "case_id": "SV-022",
        "family": "verified_learning",
        "diagnosis_status": "accepted",
        "verification_status": "failed",
    })
    truth.append({"case_id": "SV-022", "family": "verified_learning", "expected_eligible": False})

    inputs.append({
        "case_id": "SV-023",
        "family": "rollback",
        "availability": "NOT_EXECUTED",
        "reason": "execute_controlled_rollback requires DB + sandbox snapshot",
    })
    truth.append({
        "case_id": "SV-023",
        "family": "rollback",
        "exclude_from_denominator": True,
        "availability": "NOT_EXECUTED",
    })
    inputs.append({
        "case_id": "SV-024",
        "family": "rollback",
        "availability": "NOT_EXECUTED",
        "reason": "maybe_auto_rollback_controlled_patch requires DB + patch proposal",
    })
    truth.append({
        "case_id": "SV-024",
        "family": "rollback",
        "exclude_from_denominator": True,
        "availability": "NOT_EXECUTED",
    })

    if len(inputs) != 24 or len(truth) != 24:
        raise SystemExit(f"expected 24/24 got {len(inputs)}/{len(truth)}")

    _dump(HERE / "inputs.yaml", {
        "dataset_id": "supplementary_verification_24",
        "label": "SUPPLEMENTARY CONTROLLED VERIFICATION EVALUATION",
        "application_freeze_sha": APPLICATION_FREEZE_SHA,
        "case_count": 24,
        "note": "Inputs only. Ground truth is not passed to PrivacyTrace.",
        "cases": inputs,
    })
    _dump(HERE / "ground_truth.yaml", {
        "dataset_id": "supplementary_verification_24",
        "case_count": 24,
        "note": "Score only after outputs exist.",
        "cases": truth,
    })
    sealed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    combined = hashlib.sha256(
        (HERE / "inputs.yaml").read_bytes() + b"\n" + (HERE / "ground_truth.yaml").read_bytes()
    ).hexdigest()
    manifest = {
        "supplementary_eval_id": "SUPP-VERIFY-20260817-1",
        "label": "SUPPLEMENTARY CONTROLLED VERIFICATION EVALUATION",
        "application_freeze_sha": APPLICATION_FREEZE_SHA,
        "scenario_count": 24,
        "executable_count": 22,
        "not_executed": ["SV-023", "SV-024"],
        "sealed_at_utc": sealed_at,
        "inputs_sha256": _sha(HERE / "inputs.yaml"),
        "ground_truth_sha256": _sha(HERE / "ground_truth.yaml"),
        "combined_sha256": combined,
        "evaluation_harness_sha256": _harness_sha(),
        "rollback_limitation": "Frozen rollback APIs require a database session and sandbox patch; not executed.",
    }
    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"sealed": True, "combined_sha256": combined}, indent=2))


def run(run_id: str) -> Path:
    from app.models.enums import VerificationStatus
    from app.services.causality_engine import apply_staleness_to_rows, supersede_rows
    from app.services.counterfactual_analysis_service import classify_stability
    from app.services.fix_verification_service import verification_status_for_retest
    from app.services.root_cause_evidence_strength_service import (
        CausalEvidenceInputs,
        compute_causal_evidence_strength_from_context,
    )
    from app.services.verified_outcome_learning_service import eligibility_for_learning

    inputs = yaml.safe_load((HERE / "inputs.yaml").read_text(encoding="utf-8"))
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cases_out: list[dict[str, Any]] = []
    for case in inputs["cases"]:
        family = case["family"]
        row: dict[str, Any] = {"case_id": case["case_id"], "family": family}
        if family.startswith("fix_verification") or family == "mismatched_retest":
            status = verification_status_for_retest(
                dimensions_match=bool(case["dimensions_match"]),
                raw_exposure_after_change=case.get("raw_exposure_after_change"),
            )
            row["status"] = status.value if isinstance(status, VerificationStatus) else str(status)
            row["executed"] = True
        elif family == "insufficient_rca":
            if case["mode"] == "classify_stability":
                row["stability"] = classify_stability(
                    baseline_score=float(case["baseline_score"]),
                    supporting_count=int(case["supporting_count"]),
                    results=list(case.get("results") or []),
                )
            else:
                incident = SimpleNamespace(**case["incident"])
                result = compute_causal_evidence_strength_from_context(
                    CausalEvidenceInputs(incident=incident)
                )
                row["strength"] = result.get("causal_strength_level")
                row["strength_payload_keys"] = sorted(result.keys())
            row["executed"] = True
        elif family == "stale_chain":
            dummy = SimpleNamespace(
                stale=False,
                stale_reason=None,
                analysis_version=1,
                superseded_by_analysis_id=None,
            )
            if case["mode"] == "stale":
                changed = apply_staleness_to_rows([dummy], case["reason"])
                row["changed"] = changed
                row["stale"] = dummy.stale
                row["stale_reason"] = dummy.stale_reason
            else:
                changed = supersede_rows([dummy], case["new_analysis_id"])
                row["changed"] = changed
                row["stale"] = dummy.stale
                row["superseded_by_analysis_id"] = dummy.superseded_by_analysis_id
            row["executed"] = True
        elif family == "verified_learning":
            diagnosis = SimpleNamespace(status=case["diagnosis_status"])
            verification = SimpleNamespace(verification_status=case["verification_status"])
            result = eligibility_for_learning(diagnosis=diagnosis, verification=verification)
            row["eligible_for_learning"] = result["eligible_for_learning"]
            row["eligibility_reason"] = result["eligibility_reason"]
            row["executed"] = True
        elif family == "rollback":
            row["executed"] = False
            row["availability"] = "NOT_EXECUTED"
            row["reason"] = case.get("reason")
        else:
            row["error"] = f"unknown family {family}"
        cases_out.append(row)

    manifest = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    payload = {
        "supplementary_eval_id": run_id,
        "application_freeze_sha": APPLICATION_FREEZE_SHA,
        "evaluation_harness_sha256": manifest["evaluation_harness_sha256"],
        "combined_sha256": manifest["combined_sha256"],
        "start_timestamp_utc": started,
        "end_timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "application_fixes_this_run": 0,
        "cases": cases_out,
    }
    out = HERE / "outputs.json"
    if out.exists():
        raise SystemExit("Refusing to overwrite existing outputs.json")
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out


def score() -> Path:
    outputs = json.loads((HERE / "outputs.json").read_text(encoding="utf-8"))
    gt = {c["case_id"]: c for c in yaml.safe_load((HERE / "ground_truth.yaml").read_text(encoding="utf-8"))["cases"]}
    out = {c["case_id"]: c for c in outputs["cases"]}

    def acc(family: str, field: str, expected_key: str) -> dict[str, Any]:
        ids = [cid for cid, g in gt.items() if g["family"] == family and not g.get("exclude_from_denominator")]
        correct = 0
        failures = []
        for cid in ids:
            expected = gt[cid][expected_key]
            actual = out[cid].get(field)
            if actual == expected:
                correct += 1
            else:
                failures.append({"case_id": cid, "expected": expected, "actual": actual})
        n = len(ids)
        return {"n": n, "correct": correct, "accuracy": round(correct / n, 6) if n else None, "failures": failures}

    fv_pass = acc("fix_verification_pass", "status", "expected_status")
    fv_fail = acc("fix_verification_fail", "status", "expected_status")
    fv_inc = acc("fix_verification_inconclusive", "status", "expected_status")
    mismatch = acc("mismatched_retest", "status", "expected_status")
    learn = acc("verified_learning", "eligible_for_learning", "expected_eligible")

    rca_ids = [cid for cid, g in gt.items() if g["family"] == "insufficient_rca"]
    rca_ok = 0
    rca_fail = []
    for cid in rca_ids:
        g = gt[cid]
        o = out[cid]
        if "expected_stability" in g:
            ok = o.get("stability") == g["expected_stability"]
        else:
            ok = o.get("strength") == g["expected_strength"]
        if ok:
            rca_ok += 1
        else:
            rca_fail.append({"case_id": cid, "expected": g, "actual": o})

    stale_ids = [cid for cid, g in gt.items() if g["family"] == "stale_chain"]
    stale_ok = 0
    stale_fail = []
    for cid in stale_ids:
        g = gt[cid]
        o = out[cid]
        if g.get("expected_stale"):
            ok = o.get("stale") is True and o.get("changed") == g.get("expected_changed")
        else:
            ok = bool(o.get("superseded_by_analysis_id")) and o.get("stale") is True
        if ok:
            stale_ok += 1
        else:
            stale_fail.append({"case_id": cid, "expected": g, "actual": o})

    ver_ids = [
        cid for cid, g in gt.items()
        if g["family"] in {
            "fix_verification_pass",
            "fix_verification_fail",
            "fix_verification_inconclusive",
        }
    ]
    ver_ok = sum(1 for cid in ver_ids if out[cid].get("status") == gt[cid]["expected_status"])

    summary = {
        "supplementary_eval_id": outputs["supplementary_eval_id"],
        "application_freeze_sha": outputs["application_freeze_sha"],
        "application_fixes_this_run": 0,
        "fix_verification_pass_accuracy": fv_pass,
        "fix_verification_fail_accuracy": fv_fail,
        "fix_verification_inconclusive_accuracy": fv_inc,
        "overall_verification_state_accuracy": {
            "n": len(ver_ids),
            "correct": ver_ok,
            "accuracy": round(ver_ok / len(ver_ids), 6) if ver_ids else None,
        },
        "mismatched_retest_safe_handling": mismatch,
        "insufficient_evidence_rca": {
            "n": len(rca_ids),
            "correct": rca_ok,
            "accuracy": round(rca_ok / len(rca_ids), 6) if rca_ids else None,
            "failures": rca_fail,
        },
        "stale_chain_rejection": {
            "n": len(stale_ids),
            "correct": stale_ok,
            "accuracy": round(stale_ok / len(stale_ids), 6) if stale_ids else None,
            "failures": stale_fail,
        },
        "verified_learning_eligibility": learn,
        "rollback_correctness": {
            "n": 0,
            "executed": False,
            "ids": ["SV-023", "SV-024"],
            "limitation": "Frozen rollback requires DB + sandbox; NOT EXECUTED.",
        },
        "scenario_level_failures": (
            fv_pass["failures"] + fv_fail["failures"] + fv_inc["failures"]
            + mismatch["failures"] + learn["failures"] + rca_fail + stale_fail
        ),
    }
    path = HERE / "score.json"
    if path.exists():
        raise SystemExit("Refusing to overwrite existing score.json")
    path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seal", action="store_true")
    parser.add_argument("--run-id")
    parser.add_argument("--score", action="store_true")
    args = parser.parse_args()
    if args.seal:
        seal()
        return
    if args.run_id:
        print(run(args.run_id))
        return
    if args.score:
        print(score())
        return
    raise SystemExit("Use --seal, --run-id, or --score")


if __name__ == "__main__":
    main()
