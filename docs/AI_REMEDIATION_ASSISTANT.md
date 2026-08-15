# AI Remediation Assistant

## Purpose

AI Remediation Assistant adds optional, privacy-safe remediation guidance to PrivacyTrace-NP incidents. It prepares masked incident context, sends only that masked summary to a configured provider, stores the returned suggestion, and requires a human reviewer to accept, edit, or reject the suggestion.

The assistant is advisory. It does not approve incidents, close incidents, verify fixes, assign fault, or replace the existing human review and fix verification workflow.

## Disabled By Default

AI support is disabled unless explicitly enabled in backend configuration.

```env
AI_ASSISTANT_ENABLED=false
AI_PROVIDER=openai_compatible
AI_MODEL=
AI_MODEL_CANDIDATES=
AI_BASE_URL=
AI_API_KEY=
AI_BACKUP_API_KEYS=
AI_TIMEOUT_SECONDS=30
AI_MAX_INPUT_CHARS=8000
```

For local automated tests, the backend supports `AI_PROVIDER=mock` with `AI_ASSISTANT_ENABLED=true`. The mock provider returns deterministic masked-only suggestions and does not make a network call.

Backup keys and backup model candidates can be configured with `AI_BACKUP_API_KEYS` and `AI_MODEL_CANDIDATES`. They are tried only by the backend provider client and must never be exposed to the frontend or committed to source control.

OpenCode Zen inference is supported. External Zen API-key lifecycle remains provider-managed until an official machine credential-management API is available. Keep `AI_CREDENTIAL_ROTATION_ENABLED=false` for Zen. After replacing keys at the provider, run `python scripts/rotate_ai_credentials.py --preflight` and `python scripts/rotate_ai_credentials.py --validate`. Those commands never print keys.

## Privacy Boundary

The assistant builds its input from safe incident fields only:

- Incident metadata and masked summary
- Masked detections, including `masked_value`
- Evidence identifiers and metadata
- Root-cause category, confidence band, and safe remediation context
- Human review state
- Fix verification state

It does not store raw AI prompts. It stores a `masked_input_summary_hash` for traceability. Input is checked by the safety gateway before provider use. Output is checked before storage or display.

## Safety Rules

The safety layer blocks provider input or output when it contains unmasked sensitive patterns, secrets, private keys, bearer credentials, raw transaction identifiers, unsafe certainty wording, blame wording, or automatic closure wording.

Reviewer notes and reviewer-edited remediation actions are also safety checked before storage.

## API Endpoints

All endpoints are under `/ai-remediation`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/status` | Return enabled/configured/safety status |
| POST | `/incidents/{incident_id}/suggest` | Generate a masked advisory suggestion |
| GET | `/incidents/{incident_id}/suggestions` | List suggestions for an incident |
| GET | `/suggestions/{suggestion_id}` | Read one suggestion |
| POST | `/suggestions/{suggestion_id}/accept` | Record reviewer acceptance |
| POST | `/suggestions/{suggestion_id}/edit` | Save reviewer-edited remediation actions |
| POST | `/suggestions/{suggestion_id}/reject` | Record reviewer rejection |

Accepting a suggestion can create an advisory remediation action reference such as `REM-AI-*`, but it does not change incident closure state and does not create fix verification evidence.

## Access Control

- Read: admin, security analyst, DevSecOps engineer, auditor
- Generate: admin, security analyst, DevSecOps engineer
- Review accept/edit/reject: admin, security analyst, DevSecOps engineer
- Auditor: read-only
- Developer and viewer: no AI remediation access

Unauthenticated requests return `401`. Authenticated roles without permission return `403`.

## Frontend Workflow

Incident detail pages include an `AI Remediation Assistant` section after `Human Review` and before `Remediation Action`.

The panel shows:

- Provider and enabled status
- Safety notice
- Suggestion history
- Remediation actions, code/config areas, suggested tests, retest evidence, and limitations
- Reviewer accept/edit/reject controls for permitted roles

If the assistant is disabled or the provider is incomplete, generation stays unavailable and the manual remediation workflow remains usable.

## Final Reports

Final investigation reports include safe AI remediation suggestions in `ai_remediation_suggestions`. This section is advisory and keeps the existing report safety model: masked-only content, human review status, limitations, and retest evidence requirements.

## Verification

Focused backend tests cover status, generation, listing, detail read, final report inclusion, input safety blocking, output safety blocking, provider failure, role access, and reviewer workflow.

Focused frontend tests cover panel rendering, disabled-provider behavior, display sanitization, reviewer-input blocking, accept/edit/reject calls, and auditor read-only behavior.
