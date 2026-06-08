# PrivacyTrace-NP Backend

FastAPI backend for the PrivacyTrace-NP thesis prototype.

## Run locally

```powershell
# From repo root, start Postgres first
docker compose up -d

cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Optional: copy env from repo root
copy ..\.env.example .env

uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

API docs: http://127.0.0.1:8000/docs

Health: http://127.0.0.1:8000/health

## Phase 2: Database migrations and seed

After PostgreSQL is running:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Apply schema (16 tables)
alembic upgrade head

# Seed synthetic Phase 2 data (3 users, 1 incident, 2 evidence files)
python -m app.db.seed_phase2
```

Re-run seed safely: it skips if `INC-SEED-001` already exists.

## Phase 3: Evidence ingestion

Synthetic sample files live under `app/sample_data/` (Scenario 1). After PostgreSQL is running:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Optional: link samples to seed incident
python -m app.db.seed_phase2

uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Load all Scenario 1 samples (8 files):

```powershell
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/evidence/load-sample `
  -ContentType "application/json" -Body '{"scenario":"scenario_1"}'

Invoke-RestMethod http://127.0.0.1:8000/evidence
Invoke-RestMethod http://127.0.0.1:8000/evidence/EVD-S1-API-001
```

Upload a file (`.txt`, `.json`, `.csv`, `.log`):

```powershell
# Example with curl if available
curl -X POST http://127.0.0.1:8000/evidence/upload `
  -F "file=@app/sample_data/logs/wallet_transfer_api.log" `
  -F "evidence_type=api_log" `
  -F "source_system=manual-upload"
```

Phase 3 tests:

```powershell
pytest app/tests/test_phase3.py -v
```

## Phase 4: Evidence normalisation

After loading evidence (Phase 3), parse files into `normalized_events`:

```powershell
# Load samples then parse all pending files
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/evidence/load-sample `
  -ContentType "application/json" -Body '{"scenario":"scenario_1"}'

Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/evidence/parse-all

# Parse one file (optional force=true to re-parse)
Invoke-RestMethod -Method POST -Uri "http://127.0.0.1:8000/evidence/EVD-S1-API-001/parse"

# List normalised events for an evidence file
Invoke-RestMethod http://127.0.0.1:8000/evidence/EVD-S1-API-001/events
```

Supported evidence types for parsing: `api_log`, `runtime_log`, `fixed_log`, `semgrep_report`, `gitleaks_report`, `deployment_log`, `access_event`, `trivy_report`. Unsupported types (e.g. `siem_alert`) return HTTP 422 and `parsing_status=failed`.

Phase 4 tests:

```powershell
pytest app/tests/test_phase4.py -v
```

## Phase 5: Detection and masking

After parsing evidence (Phase 4), run regex detection and mask sensitive values in event messages. API responses expose only `masked_value` (never raw secrets or `raw_value_hash`).

```powershell
# Load → parse → detect
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/evidence/load-sample `
  -ContentType "application/json" -Body '{"scenario":"scenario_1"}'

Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/evidence/parse-all
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/evidence/detect-all

Invoke-RestMethod http://127.0.0.1:8000/evidence/EVD-S1-API-001/events
Invoke-RestMethod http://127.0.0.1:8000/evidence/EVD-S1-API-001/detections

# Detect one file (optional force=true to re-run)
Invoke-RestMethod -Method POST -Uri "http://127.0.0.1:8000/evidence/EVD-S1-API-001/detect"
```

Rules live under `app/rules/` (`sensitive_data_rules.yaml`, `masking_rules.yaml`).

Phase 5 tests:

```powershell
pytest app/tests/test_phase5.py -v
```

## Phase 6: Privacy Causality Engine

After detection (Phase 5), correlate evidence and rank **likely** technical root causes with confidence bands and missing-evidence lists. Outputs never claim confirmed blame.

```powershell
# Full pipeline
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/evidence/load-sample `
  -ContentType "application/json" -Body '{"scenario":"scenario_1"}'

Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/evidence/parse-all
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/evidence/detect-all

Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/incidents/analyse `
  -ContentType "application/json" -Body '{"incident_id":"INC-SEED-001"}'

Invoke-RestMethod http://127.0.0.1:8000/incidents/INC-SEED-001
Invoke-RestMethod http://127.0.0.1:8000/incidents/INC-SEED-001/trace
```

Rules: `app/rules/root_cause_rules.yaml`, `app/rules/confidence_rules.yaml`.

Phase 6 tests:

```powershell
pytest app/tests/test_phase6.py -v
```

## Phase 7: Guarded LLM Investigation Assistant

After causality analysis (Phase 6), generate **masked, evidence-grounded** investigation support via a local Ollama model or a deterministic template fallback. Raw sensitive values are never sent to the LLM or stored in reports—only a context hash and validated structured output.

**Prerequisite pipeline:** `load-sample` → `parse-all` → `detect-all` → `POST /incidents/analyse` (not `rank-causes`).

```powershell
# Full pipeline through Phase 6
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/evidence/load-sample `
  -ContentType "application/json" -Body '{"scenario":"scenario_1"}'
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/evidence/parse-all
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/evidence/detect-all
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/incidents/analyse `
  -ContentType "application/json" -Body '{"incident_id":"INC-SEED-001"}'

# Template explanation (no Ollama required)
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/incidents/INC-SEED-001/explain `
  -ContentType "application/json" -Body '{"provider":"template"}'

# List stored LLM reports
Invoke-RestMethod http://127.0.0.1:8000/incidents/INC-SEED-001/llm-reports

# Optional: Ollama (local only)
ollama pull qwen2.5:7b-instruct
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/incidents/INC-SEED-001/explain `
  -ContentType "application/json" -Body '{"provider":"ollama"}'
```

Rules: `app/rules/llm_safety_rules.yaml`. Configuration: `OLLAMA_BASE_URL`, `OLLAMA_DEFAULT_MODEL`, `OLLAMA_BACKUP_MODEL` in `.env`.

Phase 7 tests:

```powershell
pytest app/tests/test_phase7_llm_guarded.py -v
```

## Phase 8: Human review and audit trail

After running the Phase 6 analyse pipeline (load-sample → parse-all → detect-all → analyse):

```powershell
$login = Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/auth/login `
  -ContentType "application/json" `
  -Body '{"email":"analyst@privacytrace.local","password":"AnalystPass123!"}'
$headers = @{ Authorization = "Bearer $($login.access_token)" }

# Submit human review (approved | rejected | inconclusive | request_more_evidence)
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/incidents/INC-SEED-001/review `
  -Headers $headers `
  -ContentType "application/json" `
  -Body '{"decision":"approved","comment":"Cause matches masked API evidence."}'

Invoke-RestMethod http://127.0.0.1:8000/incidents/INC-SEED-001/reviews -Headers $headers
Invoke-RestMethod "http://127.0.0.1:8000/audit-logs?incident_id=INC-SEED-001" -Headers $headers
```

Review updates `incidents.status` and appends rows to `review_decisions` and `audit_logs` (action `review_submitted`). Audit `details` never store raw sensitive values.

Phase 8 tests:

```powershell
pytest app/tests/test_phase8_review_audit.py -v
```

## Tests

Phase 1 tests (no database required):

```powershell
pytest app/tests -v -m "not integration"
```

All tests including live PostgreSQL check (requires `docker compose up -d`):

```powershell
pytest app/tests -v
```

Tests cover:

1. Backend app imports successfully (`test_phase1.py`)
2. Database connection configuration loads (`test_phase1.py`)
3. `/health` returns success when DB is reachable (`test_phase1.py`)
4. `/health` returns 503 when DB is disconnected (`test_health.py`)
5. All 16 models import and unique constraints exist (`test_phase2.py`)
6. Tables, seed data, and incident-evidence links (`test_phase2.py`, requires Docker)
7. Evidence hashing, load-sample, upload, and GET metadata (`test_phase3.py`, integration requires Docker)
8. Parsers, parse-all/parse endpoints, normalized events (`test_phase4.py`, integration requires Docker)
