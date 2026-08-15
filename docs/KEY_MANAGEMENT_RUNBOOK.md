# Key management runbook (demo)

## Generate keys

```powershell
.\scripts\generate_demo_keys.ps1
```

Set paths relative to `backend/` when running uvicorn from that directory.

## Rotate keys

```powershell
.\scripts\rotate_demo_keys.ps1
```

1. Back up `keys/demo/` to timestamped folder.
2. Regenerate JWT and data-wrap pairs.
3. Update `CRYPTO_ACTIVE_KEY_ID` if versioning keys.
4. Force users to re-login (old JWTs invalid).
5. Re-encrypt at-rest data only if you implement a migration job (not automated in demo).

## Separation

| Key pair | Purpose |
|----------|---------|
| `jwt_*.pem` | Sign/verify access tokens |
| `data_wrap_*.pem` | Wrap AES DEKs for storage encryption |

Never use JWT keys for data wrapping or vice versa.

## Storage

- Private keys: `backend/keys/demo/*_private.pem` — gitignored
- Public keys: may exist locally for verification only
- Never log private key material or JWTs

## Self-check

```powershell
.\scripts\security_self_check.ps1
```

Or `GET /security/self-check` with a valid bearer token.
