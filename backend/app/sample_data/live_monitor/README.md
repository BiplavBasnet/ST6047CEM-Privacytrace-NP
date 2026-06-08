# Live Privacy Monitor sample data

All values are synthetic and used only for thesis demonstration. Do not use real customer data, real secrets, real wallet data, or production logs.

Files:

- `live_wallet_safe_events.jsonl`: events that should not create privacy alerts.
- `live_wallet_privacy_leak_events.jsonl`: synthetic events with raw-looking test values for exercising masking and alert creation.
- `live_syslog_like_events.log`: syslog-like text lines for controlled local/demo ingestion tests.

Expected behavior:

1. Safe events return `no_alert`.
2. Synthetic leak events create privacy alerts.
3. API responses, UI, reports, exports, and audit logs must show masked values only.
4. Alerts require human review and do not prove root cause.
