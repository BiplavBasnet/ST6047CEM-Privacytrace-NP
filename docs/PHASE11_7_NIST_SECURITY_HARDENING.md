# Phase 11.7 — NIST-aligned cryptographic security hardening

## Scope

Adds a **NIST-aligned**, **FIPS-aware** crypto layer without claiming formal FIPS 140-3 validation.

## Delivered capabilities

1. AES-256-GCM encryption at rest (reports, audit details, LLM output, evidence files)
2. RSA-OAEP-SHA256 key wrapping for DEKs
3. RS256 JWT when demo PEM keys are configured
4. PBKDF2-HMAC-SHA256 password hashing (bcrypt verify for legacy)
5. Security profile API: `/security/profile`, `/security/self-check`, `/security/key-status` (admin)
6. HTTP security headers middleware
7. Documentation and PowerShell key scripts

## Out of scope

- Phase 12 packaging
- New scanners / detection / causality / LLM logic changes (except encrypt/decrypt storage)
- Cloud LLM or fine-tuning
- Formal FIPS/NIST certification claims

## Verification

```bash
cd backend
pytest app/tests/test_phase11_7_crypto_security.py -v
pytest app/tests/test_phase11_7_nist_profile.py -v
```

Manual: `.\scripts\generate_demo_keys.ps1`, migrate, seed, login, call security endpoints.
