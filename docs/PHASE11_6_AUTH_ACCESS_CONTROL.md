# Phase 11.6 — Authentication and Access Control

PrivacyTrace-NP includes a thesis-scope authentication layer: PBKDF2 password hashing (with legacy bcrypt verify), JWT bearer access tokens, role-based permissions on backend routes, a split-screen login/sign-up experience, and admin user management.

## What was added

- **Backend:** `auth_service`, `password_service`, `permission_service`, `user_service`, JWT settings, `/auth/*` and `/users/*` routes, Alembic migration `006_user_auth_fields`, demo user seed script, public self-registration (`POST /auth/register`) with least-privilege `viewer` role.
- **Frontend:** Split-screen auth pages (`/login`, `/signup`), `AuthContext`, `ProtectedRoute`, `RoleGate`, user management page, Authorization header on API calls.
- **Audit:** Actions record `actor_id`, `actor_email`, and `actor_role` via the existing audit safety pipeline (including registration success/reject/disabled).

## Role permissions

| Permission | admin | security_analyst | developer | devsecops_engineer | auditor | viewer |
|------------|:-----:|:----------------:|:---------:|:------------------:|:-------:|:------:|
| incident:read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| evidence:read | ✓ | ✓ | ✓ | ✓ | — | — |
| evidence:upload | ✓ | ✓ | — | ✓ | — | — |
| incident:review | ✓ | ✓ | — | — | read | — |
| fix:verify | ✓ | ✓ | — | ✓ | — | — |
| fix:read | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| report:generate | ✓ | ✓ | — | — | ✓ | — |
| metrics:run | ✓ | ✓ | — | — | — | — |
| metrics:read | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| audit:read | ✓ | ✓ | — | — | ✓ | — |
| user:manage | ✓ | — | — | — | — | — |

## Public self-registration

| Item | Policy |
|------|--------|
| Endpoint | `POST /auth/register` |
| Status probe | `GET /auth/registration-status` |
| Default role | **`viewer` only** (never admin, analyst, auditor, DevSecOps, or other privileged roles) |
| Role from client | Rejected (`extra=forbid`; no role field accepted) |
| Password policy | At least 10 characters with uppercase, lowercase, digit, and symbol (same as admin user create) |
| Email verification | Configurable via `EMAIL_VERIFICATION_REQUIRED`; **default false**. There is no mail provider — enabling verification without a provider fails closed (no fake “email sent”). |
| After register | Account is active as `viewer`; user must sign in via `POST /auth/login` (no auto-login token on register) |

Configuration (see `.env.example`):

- `SELF_REGISTRATION_ENABLED` — demo default `true`; set `false` for production-like deploys
- `DEFAULT_REGISTRATION_ROLE` — must remain `viewer`
- `EMAIL_VERIFICATION_REQUIRED` — default `false`

## Demo accounts (synthetic only)

| Email | Password | Role |
|-------|----------|------|
| admin@privacytrace.local | AdminPass123! | admin |
| analyst@privacytrace.local | AnalystPass123! | security_analyst |
| developer@privacytrace.local | DeveloperPass123! | developer |
| devsecops@privacytrace.local | DevSecOpsPass123! | devsecops_engineer |
| auditor@privacytrace.local | AuditorPass123! | auditor |
| viewer@privacytrace.local | ViewerPass123! | viewer |
| (self-register via `/signup`) | (your password) | viewer |

**Do not use these passwords in production.**

## How to login / sign up

1. Start backend and frontend (see below).
2. Open `/login` for sign-in, or `/signup` for self-registration (when enabled).
3. Sign in with a demo account or a newly registered viewer account.
4. Use **Sign out** in the header to clear the JWT from browser storage.

The auth UI is a PrivacyTrace-NP-specific split-screen layout (form + investigation workflow visual). It is inspired by common split auth layouts and does **not** copy third-party branding or social-login buttons. Social OAuth is not provided. Password reset is not implemented — the UI does not show a dead forgot-password link.

## Run backend / frontend

```powershell
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

```powershell
cd frontend
npm run dev
```

Seed demo users (after migration):

```powershell
cd backend
python -m app.db.seed_auth_users
```

Environment (development defaults in `config.py`; override in `.env`):

- `JWT_SECRET_KEY` — replace in production
- `JWT_ALGORITHM` — default `HS256` (RS256 when demo PEMs are present)
- `ACCESS_TOKEN_EXPIRE_MINUTES` — default `480`
- `SELF_REGISTRATION_ENABLED` / `DEFAULT_REGISTRATION_ROLE` / `EMAIL_VERIFICATION_REQUIRED`

## Run tests

```powershell
cd backend
$env:REQUIRE_TEST_POSTGRES="1"
pytest app/tests/test_phase11_6_auth_access.py app/tests/test_auth_registration.py app/tests/test_auth_registration_e2e.py -v
```

```powershell
cd frontend
npm test
```

## Security limitations

This is a **thesis prototype** authentication layer. It demonstrates access control and audit identity, but it is **not** a production identity platform. Production deployment would require stronger secret management, HTTPS, refresh-token strategy, password reset, account lockout, MFA, secure cookie strategy, and external identity provider integration. Public registration should typically be disabled outside controlled demos.

JWT access tokens are stored in `sessionStorage` (legacy `localStorage` values are migrated then removed). There is no remember-me persistence and no refresh-token rotation in this prototype.

## What was not added

- Phase 12 packaging / final submission bundle
- New scanners or detection categories
- Cloud LLM or fine-tuning
- Token blacklisting / refresh tokens
- OAuth / SSO / social login
- MFA
- Password reset / email verification delivery
- Approval/`pending` registration workflow (self-registered users receive `viewer` immediately when registration is enabled; they receive no organisation membership until an admin assigns them)
- Shared-instance SaaS multi-tenancy (see `docs/ORGANISATION_DEPLOYMENT.md`)
