"""Held-out 80 runner. Loads inputs only. Score only after outputs exist.

PrivacyTrace runtime must not import ground_truth.yaml.
Application correction cycles: 0.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(BACKEND))

from rca_rank import rank_causes  # noqa: E402

APPLICATION_FREEZE_SHA = "8b22b670a82b61882cb841b10a9f4d364de30bc7"
NEPALFIN_LAB_SHA = "ae77b8ee4c62b5171c2b3ca08a44fe0ee405c0ee"


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _harness_sha() -> str:
    h = hashlib.sha256()
    for name in ("rca_rank.py", "run_heldout.py", "seal_dataset.py", "inputs.yaml", "ground_truth.yaml"):
        p = HERE / name
        if p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()


def run_outputs(run_id: str) -> Path:
    from app.services import scanner_safety_service, sensitive_exposure_engine

    inputs = _load(HERE / "inputs.yaml")
    manifest = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cases_out: list[dict[str, Any]] = []

    for case in inputs["cases"]:
        family = case["family"]
        row: dict[str, Any] = {"case_id": case["case_id"], "family": family}
        if family == "detection":
            findings = sensitive_exposure_engine.analyse(
                source_type=case["source_type"],
                text=case.get("text"),
                structured=case.get("structured"),
                environment=case.get("environment"),
            )
            row["findings"] = [
                {
                    "sensitive_type": f.get("sensitive_type"),
                    "exposure_decision": f.get("exposure_decision"),
                    "masked_value": f.get("masked_value"),
                }
                for f in findings
            ]
            blob = json.dumps(findings, default=str)
            row["raw_leak_probe_blob_len"] = len(blob)
            row["finding_blob"] = blob
        elif family == "rca":
            ranked = rank_causes(case.get("evidence_signals"), case.get("contradicting_signals"))
            row.update(ranked)
        elif family == "scanner_controlled":
            result = scanner_safety_service.sanitize_payload(case["payload"])
            sanitised = result.sanitised_payload
            row["safe"] = result.safe
            row["violation_codes"] = result.violation_codes
            row["reason"] = result.reason
            row["sanitised_payload"] = sanitised
            row["sanitised_blob"] = json.dumps(sanitised, default=str) if sanitised is not None else ""
        elif family in {"wazuh", "github_hosted_workflow"}:
            row["availability"] = "NOT_AVAILABLE"
            row["executed"] = False
        elif family in {"rbac_runtime", "human_gate_runtime"}:
            row["executed"] = False
            row["evidence_ref"] = case.get("evidence_ref")
            row["note"] = "Recorded from Phase 1 runtime; not re-executed against held-out answers."
        else:
            row["error"] = f"unknown family {family}"
        cases_out.append(row)

    payload = {
        "evaluation_run_id": run_id,
        "application_freeze_sha": APPLICATION_FREEZE_SHA,
        "evaluation_harness_sha256": _harness_sha(),
        "nepalfin_lab_sha": NEPALFIN_LAB_SHA,
        "held_out_80_sha256": manifest["held_out_80_sha256"],
        "inputs_sha256": manifest["inputs_sha256"],
        "database_fixture_seed": "privacytrace_np_037_verify / INC-LIVE-E178AEC313 (runtime DB; detection cases are offline engine calls)",
        "environment": {
            "python": sys.version.split()[0],
            "platform": sys.platform,
        },
        "start_timestamp_utc": started,
        "end_timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "case_count": len(cases_out),
        "cases": cases_out,
        "application_fixes_this_run": 0,
    }
    out_dir = HERE / "outputs"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / f"{run_id}.json"
    if out_path.exists():
        raise SystemExit(f"Refusing to overwrite existing run {out_path}")
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out_path


def _pr_f1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def score(run_path: Path) -> Path:
    outputs = json.loads(run_path.read_text(encoding="utf-8"))
    gt_doc = _load(HERE / "ground_truth.yaml")
    gt_by_id = {c["case_id"]: c for c in gt_doc["cases"]}
    out_by_id = {c["case_id"]: c for c in outputs["cases"]}

    det_tp = det_fp = det_fn = 0
    decision_checked = decision_matched = 0
    leak_checked = leak_count = 0
    det_rows: list[dict[str, Any]] = []
    rca_top1 = rca_top3 = rca_comp = rca_n = 0
    rca_failures: list[dict[str, Any]] = []
    scanner_ok = scanner_n = 0
    scanner_rows: list[dict[str, Any]] = []
    excluded: list[str] = []

    for case_id, gt in gt_by_id.items():
        out = out_by_id[case_id]
        family = gt["family"]
        if gt.get("exclude_from_denominator"):
            excluded.append(case_id)
            continue
        if family == "detection":
            expected = list(gt.get("expected_instances") or [])
            predicted = list(out.get("findings") or [])
            exp_c = Counter(item["sensitive_type"] for item in expected)
            pred_c = Counter(f["sensitive_type"] for f in predicted)
            types = set(exp_c) | set(pred_c)
            tp = fp = fn = 0
            for st in types:
                matched = min(exp_c.get(st, 0), pred_c.get(st, 0))
                tp += matched
                fp += pred_c.get(st, 0) - matched
                fn += exp_c.get(st, 0) - matched
            det_tp += tp
            det_fp += fp
            det_fn += fn
            for item in expected:
                decision = item.get("exposure_decision")
                if not decision:
                    continue
                decision_checked += 1
                same = [f for f in predicted if f["sensitive_type"] == item["sensitive_type"]]
                if any(f.get("exposure_decision") == decision for f in same):
                    decision_matched += 1
            raws = []
            if gt.get("raw_value"):
                raws.append(str(gt["raw_value"]))
            raws.extend(str(v) for v in (gt.get("raw_values") or []) if v)
            if raws:
                leak_checked += 1
                blob = out.get("finding_blob") or ""
                if any(raw in blob for raw in raws):
                    leak_count += 1
            det_rows.append({"case_id": case_id, "tp": tp, "fp": fp, "fn": fn})
        elif family == "rca":
            rca_n += 1
            ranked = out.get("ranked") or []
            gt_cause = gt["ground_truth_root_cause"]
            if ranked and ranked[0] == gt_cause:
                rca_top1 += 1
            else:
                rca_failures.append({
                    "case_id": case_id,
                    "expected": gt_cause,
                    "actual_top1": ranked[0] if ranked else None,
                })
            if gt_cause in set(ranked[:3]):
                rca_top3 += 1
            if out.get("predicted_component") == gt.get("ground_truth_component"):
                rca_comp += 1
        elif family == "scanner_controlled":
            scanner_n += 1
            raws = list(gt.get("raw_must_not_appear") or [])
            blob = (out.get("sanitised_blob") or "") + json.dumps(out.get("sanitised_payload"), default=str)
            raw_absent = all(raw not in blob for raw in raws) if raws else True
            expected_safe = gt.get("expected_safe")
            ok = (out.get("safe") is expected_safe) and raw_absent
            if ok:
                scanner_ok += 1
            scanner_rows.append({
                "case_id": case_id,
                "ok": ok,
                "safe": out.get("safe"),
                "expected_safe": expected_safe,
                "raw_absent": raw_absent,
            })

    p, r, f1 = _pr_f1(det_tp, det_fp, det_fn)
    summary = {
        "evaluation_run_id": outputs["evaluation_run_id"],
        "application_freeze_sha": outputs["application_freeze_sha"],
        "evaluation_harness_sha256": outputs["evaluation_harness_sha256"],
        "held_out_80_sha256": outputs["held_out_80_sha256"],
        "application_fixes_this_run": 0,
        "excluded_from_denominators": excluded,
        "detection": {
            "denominator": 50,
            "true_positives": det_tp,
            "false_positives": det_fp,
            "false_negatives": det_fn,
            "precision": round(p, 6),
            "recall": round(r, 6),
            "f1_score": round(f1, 6),
            "unsafe_exposure_classification_accuracy": round(
                decision_matched / decision_checked, 6
            ) if decision_checked else 0.0,
            "masking_success_rate": round((leak_checked - leak_count) / leak_checked, 6) if leak_checked else 1.0,
            "raw_sensitive_value_leak_count": leak_count,
            "cases": det_rows,
        },
        "rca": {
            "denominator": rca_n,
            "top1_correct": rca_top1,
            "top1_accuracy": round(rca_top1 / rca_n, 6) if rca_n else 0.0,
            "top3_correct": rca_top3,
            "top3_coverage": round(rca_top3 / rca_n, 6) if rca_n else 0.0,
            "component_localisation_accuracy": round(rca_comp / rca_n, 6) if rca_n else 0.0,
            "failures": rca_failures,
            "method_note": "Ranked from signals only. Ground truth was not appended to the ranked list.",
        },
        "scanner_controlled": {
            "denominator": scanner_n,
            "correct": scanner_ok,
            "accuracy": round(scanner_ok / scanner_n, 6) if scanner_n else 0.0,
            "label": "CONTROLLED SCANNER-OUTPUT IMPORT VALIDATION",
            "cases": scanner_rows,
        },
        "wazuh": {"availability": "NOT_AVAILABLE", "excluded_from_denominator": True, "ids": ["HO-075", "HO-076"]},
        "github_hosted_workflow": {
            "availability": "NOT_AVAILABLE",
            "excluded_from_denominator": True,
            "ids": ["HO-077", "HO-078"],
        },
        "rbac_runtime": {"qualitative": "PASS", "evidence_ref": ["SS-052", "SS-053"], "excluded_from_detector_denominator": True},
        "human_gate_runtime": {"qualitative": "PASS", "evidence_ref": ["SS-054"], "excluded_from_detector_denominator": True},
    }
    score_path = run_path.with_name(run_path.stem + ".score.json")
    if score_path.exists():
        raise SystemExit(f"Refusing to overwrite existing score {score_path}")
    score_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return score_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", help="EVALUATION_RUN_ID")
    parser.add_argument("--score", help="Path to outputs JSON to score")
    args = parser.parse_args()
    if args.score:
        path = score(Path(args.score))
        print(path)
        return
    if not args.run_id:
        raise SystemExit("Provide --run-id or --score")
    out = run_outputs(args.run_id)
    print(out)


if __name__ == "__main__":
    main()
