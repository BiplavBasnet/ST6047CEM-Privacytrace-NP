# Security limitations (PrivacyTrace-NP)

This project implements **NIST-aligned** and **FIPS-aware** cryptography for a thesis prototype. It is **not** formally **FIPS-certified** and does **not** constitute a NIST compliance attestation.

- Cryptography uses standard libraries (`cryptography`, `python-jose`) — not a validated FIPS 140-3 cryptographic module.
- Demo RSA keys under `backend/keys/demo/` are for local development only.
- Key management, HSM integration, and production rotation are out of scope for this phase.
- TLS termination and network security are assumed to be configured separately in deployment.

For algorithm choices and key handling, see `CRYPTOGRAPHIC_DESIGN.md` and `KEY_MANAGEMENT_RUNBOOK.md`.
