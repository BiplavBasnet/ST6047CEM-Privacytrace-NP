# Thesis evidence closure archives

Produced after `THESIS_EVIDENCE_SNAPSHOT_SHA=99a646aa55f0c126d8aa911223cc76eab7f32e9d`.  
Not part of the snapshot commit. Application archive is `git archive` of freeze SHA, not HEAD.

APPLICATION_FREEZE_SHA: `8b22b670a82b61882cb841b10a9f4d364de30bc7`

## Application archive

Path: `docs/thesis_evidence/archives/privacytrace-np-application-8b22b670.zip`  
APPLICATION_ARCHIVE_SHA256: `1db5591d8138397d4885a832569a1fc13b72e8abd63fb5694392590bdc2159e2`

Source: `git archive 8b22b670`, then stripped `backend/.pytest_runtime_cache/` and `.env` files.  
`.env.example` files remain (templates, not secrets).

## Thesis evidence archive

Path: `docs/thesis_evidence/archives/privacytrace-np-thesis-evidence.zip`  
THESIS_EVIDENCE_ARCHIVE_SHA256: `55d4054ce76c136addcf7c568f4de5ca02b519827bd68bc0dc6b6eae048ef920`

Includes ledger, EVALUATION_SUMMARY, SCENARIO_MANIFEST, THESIS_CLAIM_BOUNDARIES, README, held-out pack, supplementary verification pack, ablation results, selected screenshots.  
Excludes this `archives/` directory, `_prompt_extract.txt`, `.env`, Playwright dumps.

## Secret checks

`scripts/check_tracked_secrets.py`: passed.

Archive grep for `ptig_`, `.env`, and PEM private-key headers:

- No live `.env` files.
- No live `ptig_` tokens (only dummy `ptig_abcdefghijklmnopqrstuvwxyz` in CLI tests inside the application archive).
- PEM `BEGIN PRIVATE KEY` strings are synthetic evaluation/test fixtures (held-out YAML; `backend/app/evaluation_data`; unit tests; `scripts/test_check_tracked_secrets.py`). Not credentials.

Secret check: PASS.

## Freeze integrity

`git diff 8b22b670 HEAD -- backend frontend connectors` is only untracking of three `backend/.pytest_runtime_cache/` files. Hygiene, not behaviour.
