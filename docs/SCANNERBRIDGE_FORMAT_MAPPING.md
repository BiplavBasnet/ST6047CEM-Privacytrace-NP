# ScannerBridge-NP — Format Mapping

Neutral field mapping from external scanner outputs to canonical `scanner_evidence_records`.

## generic_secret_scanner_json

| Source | Canonical field |
|--------|-----------------|
| `findings[].rule` | `detector_name` |
| `findings[].type` | `finding_type` |
| `findings[].masked_secret` | `masked_value` |
| `findings[].file` | `source_file` |
| `findings[].line` | `line_number` |
| `findings[].severity` | `severity` |
| `findings[].confidence` | `confidence` |
| root `repository` | `repository` |

## external_secret_scanner_json

| Source | Canonical field |
|--------|-----------------|
| `DetectorName` | `detector_name` |
| `DetectorType` | `finding_type` |
| `Redacted` | `masked_value` (never `Secret`) |
| `SourceMetadata.Data.Git.file` | `source_file` |
| `SourceMetadata.Data.Git.line` | `line_number` |
| `SourceMetadata.Data.Git.commit` | `commit_id` |
| `Verified` | `verification_status` |

## gitleaks_json

| Source | Canonical field |
|--------|-----------------|
| `RuleID` | `detector_name` |
| `Description` | `finding_type` / explanation hint |
| `File` | `source_file` |
| `StartLine` | `line_number` |
| `Commit` | `commit_id` |
| `Redacted` | `masked_value` |
| `Tags` | `tags` |

## semgrep_sarif

| Source | Canonical field |
|--------|-----------------|
| `runs[].results[].ruleId` | `detector_name` |
| `message.text` | `explanation` |
| `locations[].physicalLocation.artifactLocation.uri` | `source_file` |
| `region.startLine` | `line_number` |
| `level` | `severity` |
| `properties` keys | `tags` |

## semgrep_json

| Source | Canonical field |
|--------|-----------------|
| `results[].check_id` | `detector_name` |
| `results[].path` | `source_file` |
| `results[].start.line` | `line_number` |
| `results[].extra.message` | `explanation` |
| `results[].extra.severity` | `severity` |
| `results[].extra.metadata` keys | `tags` |

## Stored metadata (all formats)

| Field | Notes |
|-------|--------|
| `raw_payload_hash` | SHA-256 of sanitised payload — **not** raw JSON |
| `evidence_reference` | Stable reference for reports |
| `finding_fingerprint` | Dedup key per finding |
| `causal_relevance_score` | 0–1, supporting evidence only |
| `safety_status` | `safe` / `rejected` |

## Rejected at boundary

- Keys: `Raw`, `Secret`, `password`, `password_hash`, private key blocks
- Unmasked phones, wallet IDs, JWTs, bearer tokens, API keys
- Overclaim phrases in `explanation`
