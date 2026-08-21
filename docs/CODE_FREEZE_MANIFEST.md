# PrivacyTrace-NP code-freeze manifest

**Status: SEALED.** This is the current integrated code-freeze baseline.

Branch: master
Timestamp: 2026-08-17
Alembic head (current freeze): `037_connector_client_event_id`
Alembic head (historical freeze record): `036_controlled_rollback_learning`

Tracked secret check (`python scripts/check_tracked_secrets.py`): **PASS** (no secret values printed).

Status at application code-freeze time:
whole-project runtime and held-out evaluation had not yet started.

Post-freeze runtime/evaluation evidence:
see `docs/thesis_evidence/EVALUATION_SUMMARY.md`.

Runtime-verification copy: check out the **final hygiene/package snapshot** below. Local `.env`, keys, dependencies, and databases are runtime state, not frozen source.

---

## HISTORICAL PREVIOUS REGRESSION BASELINE

`53aab5259296646f5a716b1e74fa60b804db441c`

These counts belong to that SHA only. Do not copy them into a new freeze.

- PostgreSQL critical: 75 passed
- Backend: 845 passed, 2 justified skips
- Frontend: 160 passed
- Build: PASS
- Fresh migration: PASS
- /health: 200

Alembic head at that freeze: `036_controlled_rollback_learning`.

## HISTORICAL POST-FREEZE ZEN COMPATIBILITY APPLICATION RE-SEAL

`5c96d9b93e5fe31df2386c85838d367ad2a8c4d3`

Change:
in the authoritative AI provider client.

Verification:

- targeted AI/provider tests: PASS
- targeted governance tests: NOT NEEDED
- live Zen connectivity: PASS

Full expensive regression:
NOT RERUN — explicit test-cost policy.

Last accepted hygiene/package snapshot for that re-seal:

- APPLICATION FREEZE: `5c96d9b93e5fe31df2386c85838d367ad2a8c4d3`
- FINAL HYGIENE/PACKAGE SNAPSHOT: `28ca0831a189cfdc54def5dd8c20330bbeb4dabd`

---

## HISTORICAL INTEGRATED CODE-FREEZE BASELINE (connector/UX)

APPLICATION_FREEZE_CANDIDATE (tested SHA):
`5bddb82531a9762ad1c4c056bc31d2b1f69604c1`

These counts belong to that SHA only. Do not copy them into a new freeze.

Hygiene/package snapshot: `120f258730951f7c7028a81ffb369bc68a5e9792`
Archive: `privacytrace-np-freeze-120f25873095.zip`

- PostgreSQL critical: 75 passed, 107.41s
- Backend: 881 passed, 2 skipped, 1769.13s
- Frontend: 173 passed, 40 files
- Build / fresh migration / health / secret check: PASS
- Alembic head: `037_connector_client_event_id`

Namespace candidate `ad6bcd232ac70bf6e5d130dc93efaef71cabb090` was not sealed: full backend had 1 failure (`test_runtime_connector_emit_creates_evidence`).

---

## CURRENT INTEGRATED CODE-FREEZE BASELINE

APPLICATION_FREEZE_CANDIDATE (tested SHA):
`8b22b670a82b61882cb841b10a9f4d364de30bc7`

This SHA accepts foreign Pydantic `ConnectorEventData` in `RuntimeConnector.emit` (dump then runtime `model_validate`) on top of the unique `privacytrace_runtime` namespace. Expensive regression below was executed against `8b22b670…`. Application behaviour was not edited after that SHA.

**DATABASE**

- Heads: 1
- Head: `037_connector_client_event_id`
- No revision 038

**POSTGRESQL CRITICAL** (dedicated `privacytrace_np_test`)

- 75 passed, 0 failed, 0 skipped
- Duration: 109.31s

**FULL BACKEND** (`python -m pytest app/tests`)

- 885 passed, 2 skipped, 0 failed
- Skips (not freeze blockers):
  - `test_ollama_explain_when_available` — Ollama is not running locally
  - `test_upgrade_028_to_029_preserves_source_bounds_and_quarantines_legacy_data` — documented in-place 028↔029 skip at later heads

**FRONTEND** (`npx vitest run` in `frontend/`)

- 173 passed, 0 failed
- 40 files
- Duration: 35.80s

**FRONTEND BUILD** (`npm run build`)

- PASS (`tsc -b && vite build`)

**FRESH DATABASE** (`privacytrace_np_emit_freeze_test` base→head)

- PASS
- `alembic current` / `alembic heads`: `037_connector_client_event_id`
- `integration_events.client_event_id` present
- unique index `uq_integration_events_source_client_event` present

**STARTUP / CONNECTOR / FRONTEND SMOKE**

- Fresh uvicorn on `127.0.0.1:8022` (8000/8010/8020/8021 already occupied)
- `GET /health`: HTTP 200, `database: connected`
- `POST /integrations/connector/v1/events` without/invalid credential: 401, process did not crash, no secret/stack leak
- production preview `/login` rendered; Integrations present in the bundle

**SECRET CHECK**

- PASS

**FINAL VERDICT: NEW INTEGRATED CODE FREEZE ACCEPTED**

## FINAL HYGIENE/PACKAGE SNAPSHOT

APPLICATION FREEZE:
`8b22b670a82b61882cb841b10a9f4d364de30bc7`

FINAL HYGIENE/PACKAGE SNAPSHOT:
`e7ca04b7ec517827a783f751fec28036f67d8762`

Archive filename: `privacytrace-np-freeze-e7ca04b7ec51.zip`

---

## Deployment model

- fresh PostgreSQL base→head supported
- one deployment = one organisation

## Non-blocking limitations

- Optional Ollama/provider test may be skipped when unavailable (`test_ollama_explain_when_available`).
- Populated legacy `028→029` in-place preservation is unsupported; empty-DB Alembic already runs `028→029`.
- Controlled patch / automatic rollback is restricted to the allowlisted controlled workspace.
- OpenCode Zen inference is supported. External Zen API-key lifecycle remains provider-managed until an official machine credential-management API is available. Use `python scripts/rotate_ai_credentials.py --preflight` and `--validate`. Do not enable `AI_CREDENTIAL_ROTATION_ENABLED` for Zen.

## Evaluation labelling

Existing development-set evaluation documents are **preliminary**. They are **not** the final independent held-out thesis evaluation.

## Runtime-verification copy contract

Whole-project real-user runtime verification must begin from the recorded freeze identities.

1. Record both the application freeze hash and the final hygiene/package snapshot before testing begins.
2. Obtain a clean working copy from the **final hygiene/package snapshot**.
3. Locally create runtime environment state (not frozen source):
   - `.env` from `.env.example`
   - `AI_ASSISTANT_ENABLED=true` and `AI_BASE_URL=https://opencode.ai/zen/v1` when using OpenCode Zen for AI Remediation
   - fresh runtime/demo keys
   - fresh dependency installations
   - fresh PostgreSQL runtime/test database
4. Do not treat `.local_eval_runtime/` generated metrics as held-out thesis evaluation.

This hygiene snapshot does not start runtime verification.
