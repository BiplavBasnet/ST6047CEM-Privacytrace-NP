# Cryptographic design (Phase 11.7)

Hybrid encryption: **AES-256-GCM** for data, **RSA-OAEP-SHA256** for data-encryption key wrapping, **RS256** for JWT when demo keys are configured.

## Symmetric layer

- Algorithm: AES-256-GCM (NIST SP 800-38D)
- Nonce: 96-bit random per encryption under a given DEK
- Associated data (AAD): `table|record_id|field|[extra]` to bind ciphertext to context

## Asymmetric layer

- RSA 4096 (demo), OAEP with SHA-256 and MGF1-SHA256
- Wraps 32-byte DEKs only — never bulk data

## Encrypted payload (version 1)

```json
{
  "version": 1,
  "alg": "AES-256-GCM",
  "key_wrap_alg": "RSA-OAEP-SHA256",
  "kid": "demo-key-001",
  "nonce": "<base64>",
  "encrypted_dek": "<base64>",
  "ciphertext": "<base64>",
  "aad": "reports|INC-001|content_json|json",
  "created_at": "<iso8601>"
}
```

## Targets at rest

| Artefact | Encrypted field | Queryable metadata |
|----------|-----------------|-------------------|
| Evidence files | `encrypted_file_path` + on-disk `.enc` | `evidence_id`, hash, status |
| Reports | `content_encrypted` | `incident_id`, `report_type` |
| Audit logs | `details_encrypted` | `action`, `target_*`, `timestamp` |
| LLM reports | `output_encrypted` | `report_id`, `incident_id` |

## Passwords

- New hashes: PBKDF2-HMAC-SHA256 with per-user salt (SP 800-63B-aligned verifier storage)
- Legacy bcrypt hashes remain verifiable for migration

## Randomness

OS CSPRNG via `secrets` / `os.urandom` / library generators — not `random.random`.
