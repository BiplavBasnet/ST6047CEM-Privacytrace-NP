PrivacyTrace-NP is a live privacy monitoring and incident traceability framework for possible sensitive data exposure in Nepalese digital financial service API log/event streams (thesis prototype).

**Phase 1:** PostgreSQL via Docker Compose, FastAPI backend skeleton, SQLAlchemy connection setup, and `GET /health`.

**Phase 2:** 16 SQLAlchemy models, Alembic migrations, Pydantic schemas, and seed data (users, incident, evidence). See [backend/README.md](backend/README.md).

## Prerequisites

- Docker Desktop (or Docker Engine + Compose)
- Python 3.11+

## Quick start

### 1. Start PostgreSQL

From this directory:

```powershell
cd /path/to/Privacytrace-NP
docker compose up -d
docker compose ps
```

Wait until the `postgres` service is healthy.

### 2. Configure environment (optional)

Copy the example env file into `backend/`:

```powershell
copy .env.example backend\.env
```

Or set `DATABASE_URL` manually (must match `docker-compose.yml`):

```powershell
$env:DATABASE_URL = "postgresql://privacytrace:privacytrace_dev@localhost:5432/privacytrace_np"
```

### 3. Migrate database

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
alembic upgrade head
```

Normal onboarding after a fresh migration is:

```text
bootstrap Platform Operator
→ /setup
→ Organisation
→ first Organisation Admin
→ company verification
→ application
```

See [docs/ORGANISATION_DEPLOYMENT.md](docs/ORGANISATION_DEPLOYMENT.md). Demo seeding (`python -m app.db.seed_phase2`) is optional development/demo support only and is not company onboarding.

### 4. Run the backend

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### 5. Health check

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Expected when PostgreSQL is running:

```json
{
  "status": "healthy",
  "service": "privacytrace-np",
  "database": "connected",
  "version": "0.1.0"
}
```

Authentication: after `/health` succeeds, complete `/setup` (bootstrap token, organisation, first Organisation Administrator, company verification) before using the application. Demo seed accounts are development/test only. See [docs/ORGANISATION_DEPLOYMENT.md](docs/ORGANISATION_DEPLOYMENT.md) and [docs/PHASE11_6_AUTH_ACCESS_CONTROL.md](docs/PHASE11_6_AUTH_ACCESS_CONTROL.md).

### 6. Run tests

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pytest app/tests/test_health.py -v
```

Database-backed tests require PostgreSQL and an explicit opt-in:

```powershell
# from repo root — starts the test Compose DB, sets REQUIRE_TEST_POSTGRES=1
python scripts/run_backend_tests_with_postgres.py
```

Or run pytest yourself with `REQUIRE_TEST_POSTGRES=1` and a `*_test` PostgreSQL
`DATABASE_URL`. Without that flag, conftest refuses DB-backed tests.

Static checks (from `backend/`):

```powershell
ruff check app app/tests
python -m compileall -q app
```

> **Warning:** the backend test suite drops and recreates all tables in the
> database pointed to by `DATABASE_URL`. Do not run `pytest` against a database
> whose data you want to keep, and do not run it while using the demo app.
> After a test run, restore the demo environment with:
> `alembic upgrade head`, `python -m app.db.seed_phase2`, and
> `python -m app.db.seed_auth_users`.

## Stabilisation status

Stabilisation repairs currently cover:

- **Provenance** — single `record_system_provenance` path; callers own commit; integrity append is explicit.
- **Privacy-impact taxonomy wiring** — assessments merge taxonomy classifications and current exposure profiles with detections.
- **Restricted AML / AI** — external channels (including `external_ai`) are fail-closed; AI payloads are sanitised before send.
- **Causality evidence roles** — role buckets on scored causes; retest evidence does not strengthen the original cause score.
- **Integrity** — one global hash chain with scope membership; `verification_mode=global_with_scope_membership`; failed verify blocks export.
- **Alert operations** — escalation context flags (`failed_containment`, `failed_notification_delivery`, `integrity_failure`) match correctly; metrics expose unresolved counts and median sample sizes.

See focused docs under `docs/` for each area.

## Detection language (keep these separate)

| Term | Meaning in this prototype |
| --- | --- |
| **Detection** | Masked pattern/taxonomy match that a sensitive field may be present. |
| **Exposure profile** | Combination-rule assessment of how detected categories co-occur. |
| **Suspected breach alert** | Internal `BreachAlert` in `suspected` state; not a verified breach. |
| **Verified breach** | Requires approved privacy-impact assessment plus human-reviewed incident verification. |
| **Rule score** | Deterministic weighted score from YAML rules (causality, impact, exposure). |
| **Calibrated probability** | Not produced. Do not treat rule scores as probabilities. |

## Project layout (Phase 1)

```text
Privacytrace-NP/
  docker-compose.yml
  .env.example
  backend/
    app/
      main.py
      config.py
      database.py
      routers/health_router.py
      ...
    requirements.txt
```

See [PROJECT_INSTRUCTIONS.md](PROJECT_INSTRUCTIONS.md) and [PRIVACYTRACE_RULES.md](PRIVACYTRACE_RULES.md) for the full build plan.

## Root-Cause and Traceability Engine

PrivacyTrace-NP does not prove blame. It ranks likely causes based on available privacy-safe evidence.
Confidence is reduced when evidence is missing, weak, stale, or contradictory.
Human review remains required.


## Live Privacy Monitor

Live Privacy Monitor is the primary workflow. It provides near-real-time privacy alerting from copied HTTP JSON, syslog-like and generic API log line events, masks values before display, creates privacy alerts, and lets authorised users link alerts into incident traceability.

Evidence Import remains available for historical logs, supporting evidence and retest evidence. Live alerts and imported logs are symptom evidence; technical supporting evidence and human review are required before stronger likely-cause conclusions. The monitor complements existing monitoring platforms and does not block API traffic.

See [docs/LIVE_PRIVACY_MONITOR.md](docs/LIVE_PRIVACY_MONITOR.md).

## Connector CLI

Runtime, Wazuh, and GitHub Actions connectors are installed with the local CLI
`privacytrace-connect`. Public npm registry distribution: **NOT PUBLISHED**.

From this repository root, after creating an Integrations access token:

```text
npx --yes --package=file:./connectors/cli privacytrace-connect add runtime
```

Manual file-based setup remains on Integrations. See [docs/CONNECTOR_FRAMEWORK.md](docs/CONNECTOR_FRAMEWORK.md) and [connectors/cli/README.md](connectors/cli/README.md).

## AI Remediation Assistant

PrivacyTrace-NP now includes an optional AI Remediation Assistant for privacy-safe, human-reviewed remediation suggestions. It is disabled by default, sends only masked incident summaries to a configured provider, stores advisory suggestions, and lets authorised reviewers accept, edit, or reject them.

The assistant does not approve incidents, close incidents, verify fixes, assign fault, or replace retest evidence. Manual remediation remains available when AI is disabled or unconfigured.

OpenCode Zen inference is supported. External Zen API-key lifecycle remains provider-managed until an official machine credential-management API is available.

See [docs/AI_REMEDIATION_ASSISTANT.md](docs/AI_REMEDIATION_ASSISTANT.md).

## Stop services

```powershell
docker compose down
```

