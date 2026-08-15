# Detection Pipeline Responsibilities

**Modules:** `sensitive_candidate_detection_service` → `sensitive_exposure_engine` → `detection_service` / `live_monitor_service`.

| Stage | Owns | Does not own |
|---|---|---|
| Candidate detection | Regex/taxonomy candidates from text/structured payloads | Exposure decisions, persistence |
| Exposure engine | Masking, confidence, exposure_decision, HMAC `value_fingerprint` | DB writes |
| Detection service | Persist `Detection` rows for evidence events | Live alert grouping |
| Live monitor | Alert creation/recurrence + correlation keys | Root-cause claims |

Both Evidence and Live Monitor paths call the same exposure engine. Fingerprints are HMAC-only (see `SENSITIVE_FINGERPRINTING_MODEL.md`).
