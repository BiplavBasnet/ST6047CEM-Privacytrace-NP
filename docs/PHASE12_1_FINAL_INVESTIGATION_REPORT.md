# Phase 12.1 — Privacy-Safe Final Investigation Report

## Scope

Phase 12.1 adds an all-in-one **final investigation report** export for a single incident. It aggregates existing PrivacyTrace-NP data only — no new analysis engines, no automatic closure, no blame assignment.

**Out of scope for Phase 12.1**

- Phase 12 full finalisation (packaging, thesis bundle, demo screenshots)
- Deployment / production hardening
- New LLM providers or cloud LLM
- Raw evidence file bundling

## Export formats

| Endpoint | Format |
|----------|--------|
| `GET /reports/incidents/{incident_id}/final-report.pdf` | PDF |
| `GET /reports/incidents/{incident_id}/final-report.html` | HTML |
| `GET /reports/incidents/{incident_id}/final-report.json` | JSON |
| `GET /reports/incidents/{incident_id}/evidence-summary.csv` | CSV metadata |
| `GET /reports/incidents/{incident_id}/final-report-bundle.zip` | ZIP (PDF + HTML + JSON + CSV + README) |

Permission: `report:generate`

## Report sections

1. Cover / confidentiality notice  
2. Executive summary  
3. Incident details  
4. Detection summary (masked values only)  
5. Evidence chain  
6. Normalised events (masked messages)  
7. Root-cause ranking (likely-cause wording)  
8. ScannerBridge-NP supporting evidence (if linked)  
9. Guarded explanation (template or local guarded LLM)  
10. Human review  
11. Fix verification  
12. Audit trail summary (sanitised details)  
13. Recommendations  
14. Privacy and safety controls  
15. Limitations  
16. Appendix  

## Safety

- `report_safety_service` sanitises all text before export.
- Forbidden keys (`raw_payload`, `password`, `Secret`, etc.) are stripped from structured output.
- Overclaim phrases are replaced or blocked.
- Scanner format names may appear in JSON as technical `source_format` values; main report body uses **ScannerBridge-NP** branding only.

## PDF generation

ReportLab (`reportlab==4.2.5`) — programmatic PDF without browser automation.

## Developer note

External scanner format identifiers (e.g. `gitleaks_json`) may appear in structured JSON for traceability. They are not used as product branding in PDF/HTML cover content.
