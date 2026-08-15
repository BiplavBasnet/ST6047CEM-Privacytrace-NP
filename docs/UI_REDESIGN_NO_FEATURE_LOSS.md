# UI redesign — no-feature-loss contract (Wazuh-inspired console)

Every existing route and important function remains reachable. Status is PRESERVED, MOVED, or INTENTIONALLY REDIRECTED TO EQUIVALENT CANONICAL SURFACE. None may disappear silently.

| BEFORE ROUTE | FUNCTION | PRIMARY ACTIONS | BACKEND CALLS | PERMISSION | AFTER LOCATION | STATUS |
|---|---|---|---|---|---|---|
| `/login` | Sign in | Sign in | `authApi.login` | public | `/login` | PRESERVED |
| `/signup` | Register | Create account | `authApi.register` | public | `/signup` | PRESERVED |
| `/setup` | Org onboarding + verification | Submit / verify DNS / email / continue | `setupApi.*` | public | `/setup` | PRESERVED |
| `/reset-password` | Password recovery | Request / update | `passwordResetApi.*` | public | `/reset-password` | PRESERVED |
| `/` | Privacy operations command center | Current-priority CTA | `getHealth`, `listIncidents`, live status/alerts | assigned; live gated | `/` (title: Privacy operations) | PRESERVED |
| `/live-monitor` | Live ingest + triage | Start/stop, DEMO test event, create incident, dismiss | `liveMonitorApi.*` | `live_monitor:*` | `/live-monitor` + shared `DetailInspector` | PRESERVED |
| `/alerts` | Alert triage queue | Open alert / **create or open incident**, filters, ops panel | `listAlerts`, `createIncident`, `alertOperationsApi` | `live_monitor:read`; create needs `live_monitor:incident` | `/alerts` + shared `DetailInspector` | PRESERVED (create-incident MOVED onto this queue; same API as Live Monitor) |
| `/incidents` | Incident list | Open incident | `listIncidents` | assigned | `/incidents` | PRESERVED |
| `/incidents/:id` | Workspace entry | Redirect to stage | workspace fetches | `incident:read` | `/incidents/:id/{stage}` | INTENTIONALLY REDIRECTED TO EQUIVALENT CANONICAL SURFACE |
| `/incidents/:id/overview` | What happened | Next action, privacy response | impact/alerts/subjects/governance | stage perms | same, inside `InvestigationShell` | PRESERVED |
| `/incidents/:id/root-cause` | Likely cause + traceability | Run RCA, stability analysis, advanced panels | `analyseIncident`, counterfactual, graph | `workflow:analyse` | same; Summary/Evidence/Timeline/Technical tabs | PRESERVED (`root-cause` aliases preserved) |
| `/incidents/:id/review` | Human decision | Submit decision, notifications | `submitReview`, notification APIs | `incident:review` | same; decision split layout | PRESERVED |
| `/incidents/:id/remediation` | Human-owned fix record | Generate/accept diagnosis, save action, containment, preventive | AI + remediation + privacy response | review/AI/containment | same; Recommendation/Implementation/Alternatives/Provenance | PRESERVED |
| `/incidents/:id/verification` | Implementation → test → retest → verify | Record/run/verify | `remediationLifecycleApi.*` | `fix:verify` | same | PRESERVED |
| `/incidents/:id/report` | Final report | Download PDF/ZIP | readiness, `downloadFinalReport` | `report:generate` | same; Summary/Verification/Provenance/History | PRESERVED |
| `/evidence` | Evidence import | Import / demo sample / metadata | `uploadEvidence`, `loadSampleEvidence` | `evidence:*` | `/evidence` sequential upload flow | PRESERVED |
| `/wizard` | Demo 10-step walkthrough | Run Full Analysis / per-step | workflow APIs | per-step | `/wizard` labelled DEMO; points at workspace | PRESERVED |
| `/guided-investigation` | Same wizard | same | same | same | same component | PRESERVED |
| `/demo` | Scripted demo guide | Open destinations | none | auth | `/demo` | PRESERVED |
| `/help/demo` | Same demo guide | same | none | auth/unassigned | `/help/demo` (Help nav, not “More”) | PRESERVED |
| `/integrations` | Tokens, test event, SOC export | Create/revoke token, send test, export | `integrationsApi.*` | `integration:*` | `/integrations` tabs: Overview / Connectors / Access Tokens / Developer Setup / Exports | PRESERVED |
| `/scanner-bridge` | Scanner import/correlate | Preview, import, correlate | `scannerBridgeApi.*` | `scanner_bridge:*` | `/scanner-bridge` | PRESERVED |
| `/reports` | Report index | PDF/ZIP | list/readiness/download | `report:generate` | `/reports` | PRESERVED |
| `/metrics` | Thesis evaluation metrics | Run evaluation | `getEvaluationMetrics`, `runEvaluation` | `metrics:read/run` | `/metrics` (Reference nav) | MOVED (nav group only; route unchanged) |
| `/users` | Invite + membership | Invite, role, suspend, revoke | `/users*` | `user:manage` | `/users` table + inspector | PRESERVED |
| `/security` | Crypto/NIST profile | read | `getSecurityProfile` | assigned | `/security` (Reference nav) | MOVED (nav group only; route unchanged) |
| `/taxonomy` | Nepal taxonomy | filter | `taxonomyApi.list` | `taxonomy:read` | `/taxonomy` (Reference nav) | MOVED (nav group only; route unchanged) |
| `/audit-logs` | Audit table | read | `listAllAuditLogs` | `audit:read` | `/audit-logs` + row inspector | PRESERVED |
| `/help/guide` | User guide | search/TOC/links | none | auth | `/help/guide` | PRESERVED |
| `/help/about` | Scope / not-scope | read | none | auth | `/help/about` | PRESERVED |

Nav groups after redesign (RBAC unchanged):

- **Operations:** Dashboard, Live Monitor, Alerts, Incidents, Reports
- **Data & sources:** Integrations, Evidence Import, ScannerBridge-NP
- **Management:** Users, Audit Logs
- **Reference:** Security, Taxonomy, Metrics
- **Help:** User Guide, Demo Guide, About (no desktop “More”)

Incident stage aliases (`root-cause-traceability`, `human-review`, `fix-verification`, `final-report`, hash redirects, `?alert=`, `?incident=`, `?privacy-view=`) remain valid.

Wizard is **not** in the sidebar. It remains reachable at `/wizard` and `/guided-investigation`.

Features removed: **NONE**.
Routes removed: **NONE**.
Backend changes: **NONE**.
