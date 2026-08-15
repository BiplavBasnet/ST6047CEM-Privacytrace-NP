# Root-Cause Traceability Engine

## Purpose
PrivacyTrace-NP strengthens incident investigation by ranking likely technical causes from privacy-safe evidence, instead of behaving like a basic sensitive-data scanner.

## Why This Is Stronger Than a Scanner
- A scanner answers **what leaked**.
- PrivacyTrace-NP also explains **why it likely leaked**, **which evidence supports or weakens that ranking**, and **what evidence is still missing**.

## Evidence Workflow
Sensitive exposure detected -> masked value stored -> evidence chain linked -> likely causes ranked -> human review required -> fix verification tracked.

## Signal Matching
The engine evaluates structured signals with:
- positive signals
- negative signals
- contradiction signals
- time-window correlation checks

Each matched signal stores safe reasoning and supporting evidence IDs.

## Evidence Roles
Scored causes attach role buckets (with reasons), for example:
- primary_symptom — log / runtime symptom evidence
- direct_technical_cause_evidence — matched code or secret-scan signals
- temporal_context — deployment timing
- access_control_context — access events (possible contribution only)
- dependency_context — dependency findings
- supporting_context — other matched support
- contradiction — weakening evidence
- verification_evidence — retest / fixed evidence, kept separate

Migration `019_root_cause_evidence_roles` adds `context_evidence_ids`,
`remediation_evidence_ids`, and `retest_evidence_ids` on `root_cause_scores`.

## Retest does not strengthen the original score
Signals matched solely on retest evidence types (`fixed_log`, `fixed_scan`) are
treated as unmatched for scoring weight. Retest IDs are recorded as
`verification_evidence` / `retest_evidence_ids` so a successful retest proves
fix verification, not that the candidate was the original root cause.

## Missing-Evidence Suggestions
Missing items include suggested actions, for example:
- upload deployment evidence
- upload access-control logs
- upload retest evidence
- request human analyst review

## Evidence Graph
`GET /incidents/{incident_id}/evidence-graph` returns privacy-safe nodes and edges across incident, evidence, detections, and likely causes.

## Access-Control Safety Limitations
Access-control analysis is treated as **possible contribution** only. The engine does not claim confirmed BOLA/IDOR, confirmed attacker access, or developer fault.

## Human Review Requirement
Root-cause ranking is evidence-guided and uncertainty-aware. Human review remains required before remediation conclusions.

## Limitations
- Ranking quality depends on evidence completeness.
- Contradictory or stale evidence lowers confidence.
- Rule scores are deterministic weights, not calibrated probabilities.
- The system supports investigation; it does not prove blame or legal responsibility.
