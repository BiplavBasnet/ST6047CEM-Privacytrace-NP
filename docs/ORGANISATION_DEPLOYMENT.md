# Organisation-isolated deployment

PrivacyTrace-NP currently follows an organisation-isolated deployment model: one deployment and database serve one organisation. Full shared-instance SaaS multi-tenancy and cross-tenant isolation are outside the Bachelor-level prototype scope.

This is intentional architecture, not a missing bug.

## Fresh install (required order)

1. Set `PRIVACYTRACE_BOOTSTRAP_TOKEN` (and production SMTP settings when not using demo).
2. Run migrations: `alembic upgrade head` (current head: `037_connector_client_event_id`).
3. Create the Platform Operator (not an Organisation Admin):

```bash
cd backend
python -m app.db.bootstrap_platform_operator \
  --email op@example.com \
  --name "Platform Operator" \
  --password 'ChooseAStrongPassword123!'
```

4. Open `/setup`, enter the bootstrap token with company + first Organisation Admin details.
5. Complete legal / domain / admin-email verification (or Platform Operator manual review).
6. After `overall_verification_status == verified`, the first admin can invite employees.

The bootstrap token is single-use (hash stored on `deployment_setup`). It is never logged or returned by the API.

## Company onboarding

Fresh install → `/setup` (bootstrap token) → pending Organisation + pending first admin → verification policy → activate → invites.

Demo seed accounts (`admin@privacytrace.local` and related `*.local` users) are development/test only. They are not company onboarding.

`COMPANY_VERIFICATION_MODE=demo` is blocked in production-like `APP_ENV`. Demo may surface one-time email/invite/reset tokens in API responses when SMTP is off; production must use SMTP and never returns raw tokens.

## Membership and recovery

Organisation access comes from `OrganisationMembership`, not from `user.role` alone. Uninvited `/signup` creates a viewer account with no organisation membership and no company data access.

Invitation tokens are stored as SHA-256 hashes only, single-use, and expiring.

Last Organisation Admin cannot demote/disable themselves. Platform Operator can:

- `POST /organisation/suspend` — suspend the organisation (blocks invites and integration ingest)
- `POST /organisation/recover-admin` — restore an Organisation Admin after lockout

Password reset: `POST /auth/password-reset/request` and `POST /auth/password-reset/confirm` (hashed, single-use tokens).

## Out of scope / deferred

- MFA / TOTP
- Automatic retention scheduler
- Full SaaS multi-tenancy / tenant switching
- Multiple active companies in one database
- Cross-company Platform Admin SaaS console
- Billing / subscriptions
- Multiple DNS resolver libraries (DoH URL/timeout/retry knobs only)

Verified outcome learning stays local to this deployment/organisation.
