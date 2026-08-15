# NIST security profile mapping

**NIST-aligned thesis prototype** — not formal certification.

## NIST Cybersecurity Framework 2.0

| Function | PrivacyTrace-NP alignment |
|----------|---------------------------|
| **Govern** | RBAC policy, crypto policy docs, limitations documented |
| **Identify** | Evidence/incident inventory, role inventory, data classification (masked vs encrypted) |
| **Protect** | AuthN/Z, PBKDF2 passwords, AES-GCM at rest, RSA key wrap, RS256 JWT, safety masking |
| **Detect** | Audit logs, permission-denied events, leak/overclaim tests, `/security/self-check` |
| **Respond** | Review workflow, incident status, fix verification, reports |
| **Recover** | Demo key rotation script, seed/reset, encrypted evidence backup path |

## NIST SP 800-series mapping

| Document | Controls / topics | Implementation |
|----------|-------------------|----------------|
| **SP 800-53 Rev. 5** | AC | RBAC, route permissions |
| | AU | Audit logs (encrypted details when enabled) |
| | IA | Login, JWT sessions, password verifiers |
| | SC | TLS assumed external; crypto at rest in app |
| | SI | Tamper-detecting GCM, safety scans on decrypt |
| | CM | Env-based crypto config, `.gitignore` for keys |
| | IR | Incident lifecycle, reports |
| | RA | Thesis evaluation metrics (not formal RA program) |
| | CP | Demo backup via key rotation folder |
| **SP 800-63B** | Verifier storage | PBKDF2-HMAC-SHA256 + salt; bcrypt legacy verify |
| **SP 800-57** | Key lifecycle | Demo generation, rotation runbook, `kid` in payloads |
| **SP 800-38D** | AEAD | AES-256-GCM |
| **SP 800-56B** | Key transport | RSA-OAEP-SHA256 DEK wrapping |
| **SP 800-90A** | Randomness | OS/library CSPRNG |
| **SP 800-61** | Incident handling | Workflow + audit trail |
| **SP 800-92** | Log management | Structured audit, encrypted sensitive details |
| **SP 800-122** | PII protection | Masking + encryption at rest |

See also `PHASE11_7_NIST_SECURITY_HARDENING.md` and `SECURITY_LIMITATIONS.md`.
