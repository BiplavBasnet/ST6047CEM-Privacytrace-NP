# Audit Integrity Model

Audit rows (`audit_service.log_action`) record actor, action, target, and safe details. Optional `previous_entry_hash` / `entry_hash` columns support chained integrity verification (`integrity_ledger_service`). Exports may be blocked when integrity verification fails.

See `docs/INTEGRITY_VERIFICATION.md` and `docs/CRYPTOGRAPHIC_DESIGN.md`.
