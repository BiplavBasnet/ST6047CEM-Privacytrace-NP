# AI and Playbook Responsibility Model

Clear split: **deterministic playbook selects**; **AI adapts/explains**. AI does not independently discover primary remediation.

## Responsibilities

| Actor | Does | Does not |
|---|---|---|
| Deterministic playbook | Selects primary remediation type from root-cause + exposure + sensitive-type | Invent file paths; close incidents |
| AI layer | Adapts wording, explains why-this-remediation, may enrich steps within gates | Override playbook primary type; claim unsupported source locations |
| Human | Accept / edit+accept / reject / more evidence | Relinquished — system never auto-accepts |
| Controlled patch | Applies allowlisted unified diff to sandbox | Push to prod; run without acceptance |

## Diagnosis gates

- Requires approved root-cause review bound to the **current** `RootCauseAnalysis` (`assert_valid_review_for_remediation`).
- Exact source location must be evidence-backed (`exact_source_location_known`); otherwise UI shows “Not established”.
- Unsafe proposals (e.g. disable-auth / disable-all-logging) are counted against evaluation — see AI remediation metrics.

## Generation mode

Persisted on `RemediationDiagnosis.generation_mode`:

| Mode | Meaning |
|---|---|
| `playbook` | Deterministic playbook only |
| `playbook_plus_ai` | Playbook selected primary; AI enriched wording |
| `fallback_playbook` | AI attempted and failed; playbook used |

AI does not override playbook primary remediation type.

Provider enrichment is limited to rationale, evidence-alignment wording, and
limitations. Implementation steps, tests, retest requirements, remediation type,
and all source claims remain deterministic server-owned fields. Disabled or
unconfigured AI uses `playbook`; an attempted timeout, rate-limit, malformed,
unsafe, or schema-invalid response persists `fallback_playbook` with a categorical
failure type and no exception/provider text.

## Gold-standard illustration

Playbook primary: redact Authorization before serialisation in `log_request_headers`.  
AI role: explain the header-logging cause and adapt text.  
Human: edit/accept with `original_ai_payload` preserved.  
Patch: sandbox-only diff `redact=False` → `redact=True`.

## Thesis claim language

Prefer: “playbook-selected, human-approved, AI-assisted remediation.”  
Avoid: “AI discovered and fixed the root cause autonomously.”
