# Core Engine Baseline Audit

**Phase:** UNIFIED CONTEXT-AWARE SENSITIVE-DATA EXPOSURE ENGINE  
**Date:** 2026-08-09  
**Scope:** Read-only inspection before implementation. No behaviour change in this document.

## 1. Existing detection paths

| Path | Primary service | Persists |
|------|-----------------|----------|
| Evidence / Phase-5 regex | `detection_service.py` + `rules/sensitive_data_rules.yaml` | `Detection` (+ SHA-256 `raw_value_hash`) |
| Live Monitor regex | `live_monitor_safety_service.py` (hardcoded patterns) | Match metadata in memory → `PrivacyAlert` |
| Contextual / Nepal taxonomy | `contextual_detection_service.py` + `privacy_ingestion_pipeline_service.py` | `SensitiveDataClassification` (HMAC fingerprint) |
| SIEM / Universal Integration | `siem_import_service.py` → `live_monitor_service.process_event` | Alert + `NormalizedEvent` + in-memory canonical record |
| Scanner bridge | `scanner_bridge_service.py` | `SecretFinding` / `SastFinding` + optional taxonomy (fingerprint off) |
| Safety-only scanners | `llm_safety_service`, `ai_safety_gateway`, `scanner_safety_service`, `integration_validation_service`, `audit_safety_service` | Reject / remask only — no Detection |

## 2. Overlapping responsibilities

1. **Duplicated regex catalogs** across YAML, Live Monitor, LLM safety, AI gateway, scanner safety, integration validation — drift risk.
2. **Live Monitor dual path:** regex + taxonomy on one event; type names diverge (`wallet_id` vs `wallet_identifier`).
3. **Three confidence systems:** float on Detection, string labels on classifications, hardcoded `0.92` when linking live alert → Detection.
4. **Presence vs exposure:** no first-class exposure-location or policy decision; any sensitive match can become an alert.
5. **Fingerprint split:** plain SHA-256 on Detection; HMAC on taxonomy classifications; live→Detection stores `raw_value_hash=None`.

## 3. Canonical models (current)

- `Detection` — evidence-path findings (`sensitive_type`, `confidence`, `raw_value_hash`, mask fields).
- `PrivacyAlert` — live alerts (`sensitive_types`, `masked_values`, correlation metadata JSON); **no** `repeat_count` / `first_seen` / `last_seen` columns (API always synthesises `repeat_count=1`).
- `SensitiveDataClassification` — Nepal taxonomy rows with HMAC fingerprint.
- `NormalizedEvent` — durable event row; has `release_version`; **no** `trace_id` / `request_id` / `correlation_id` / `deployment_version` columns.
- `RootCauseScore` — ranked candidates from `causality_engine.py` + `root_cause_rules.yaml`.

## 4. Correlation fields

| Field | Durable? |
|-------|----------|
| `NormalizedEvent.release_version` | Yes (from deployment_version map) |
| `trace_id` / `request_id` / `correlation_id` on NormalizedEvent | No |
| Integration `correlation_keys` map | Process memory only (`OrderedDict`, max 1000) |
| `PrivacyAlert.missing_metadata`, `correlation_recommendations` | Yes (JSON) |
| `EvidenceProvenance.trace_id` | Column exists; gateway path does not fill it |

## 5. In-memory state

- `live_monitor_config_service._STATE` — running, counters, last event/alert times (process-global).
- `siem_import_service._INTEGRATION_EVENT_STORE` — OrderedDict LRU of safe integration event views; GET-by-id fails after restart/eviction even if DB rows remain.

## 6. Root-cause inputs (current)

- Keyword/YAML signal matching in `causality_engine.py`.
- Context: detections, evidence, deployments, scanner findings, remediations (stored but not weighted into causal score).
- Retest evidence explicitly excluded from causal weights.
- Separate `root_cause_evidence_strength_service.py` **does** boost score for review / remediation / retest / verification — mixes causal and post-remediation concepts.
- Evidence graph (`evidence_graph_service.py`) is relationship/display, not causal correlation graph with strengths/reasons.

## 7. Evaluation methodology (current)

- `evaluation_metric_service.py`: **type-set** precision/recall (`detected ∩ labelled` on sensitive_type), not instance-level TP/FP/FN.
- Root-cause metrics: scenario top-1 / top-3 accuracy.
- Evidence faithfulness risk: non-empty supporting IDs can overstate support without claim–evidence role checks.

## 8. Input vs output safety

Separated in practice:

- Input: `llm_safety_service.validate_input_context`, `ai_safety_gateway`, live/scanner/integration validators.
- Output claims: `llm_safety_service.validate_investigation_output`, `ai_output_safety_service`, `report_safety_service`, `audit_safety_service`.

Gap: imported evidence phrases like “confirmed breach” may still be conflated with PrivacyTrace-generated claim policy in some paths; needs explicit two-layer contract.

## 9. Migration risks (empty PostgreSQL)

- Linear chain `001` … `020` intact.
- `001_initial_schema.py` uses `Base.metadata.create_all()`; `env.py` mitigates empty DB with subset metadata excluding post-initial tables.
- Unguarded `add_column` in `018` / `020`; `019` uses `IF NOT EXISTS`.
- Offline Alembic path may not apply the empty-DB subset filter.
- Documented test conflict: full `create_all` then upgrade → duplicate columns.

## 10. Hardcoded confidence hotspots

- Detection YAML / default `0.9` (`detection_service.py`).
- Live match floats `0.82–0.98` then discarded; incident link forces `confidence=0.92` (`live_monitor_service.py`).

## 11. Confirmed architectural problems (phase drivers)

1. Presence not distinguished from unsafe exposure.
2. Multiple conflicting detection paths and type names.
3. Inconsistent / hardcoded confidence.
4. Plain SHA-256 for low-entropy identifiers on Detection path.
5. Alert grouping incomplete (repeat fields synthetic).
6. Live Monitor state in process memory.
7. Integration canonical view in process memory.
8. Correlation IDs not durable on NormalizedEvent.
9. Evidence graph weak for causal correlation.
10. Root-cause over-reliant on keyword rules; structured exposure facts missing.
11. No staleness / versioning on root-cause analysis.
12. Causal vs post-remediation strength mixed in evidence-strength path.
13. Evaluation category-level, not instance-level.
14. Input vs output safety need sharper separation contract.
15. Empty-DB migration must be verified without relying on `create_all` as success substitute.

## 12. Implementation order (locked)

A baseline (this doc) → B taxonomy → C candidates/validators → D exposure policy → E confidence/FP → F finding model → G HMAC → H unify Live/Evidence → I alert grouping → J persist Live/integration → K durable correlation → L–O root cause → P safety → Q evaluation → R Alembic → S full regression.

No unrelated features. No UI redesign beyond minimal engine exposure.
