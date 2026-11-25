# SafeGuard backend

FastAPI + async SQLAlchemy (PostgreSQL) + Redis.

```
app/
  main.py              app factory + lifespan (engine, Redis, SMS sender)
  models.py            SQLAlchemy models
  core/
    config.py          settings from env / .env (fails fast on unsafe production config)
    logging.py         JSON/text logs, request id on every line
    middleware.py      request id + access log
    exceptions.py      AppError hierarchy        error_handlers.py  one JSON error shape
    security.py        JWT, OTP hashing, gateway HMAC   phone.py  E.164 normalisation
    ratelimit.py       Redis fixed-window limiter  redis.py
  db/session.py        engine + session factory
  api/
    deps.py            DB/Redis/current user/roles/gateway dependencies
    router.py          versioned API (/v1)    routes/auth.py, routes/health.py
  services/            auth_service.py, sms.py
  schemas/             request/response models
migrations/            Alembic
tests/
```

## Run

```bash
pip install -r requirements-dev.txt
cp .env.example .env            # set SECRET_KEY etc.
mkdir -p migrations/versions
alembic revision --autogenerate -m "initial schema"   # review it, then:
alembic upgrade head
uvicorn app.main:app --reload   # docs at /docs (disabled in staging/production)
```

## Conversational assistant

SafeGuard Smart and Lite send typed message turns to the in-process conversation
adapter at `POST /v1/conversation/adapter-turn`. The adapter runs inside the
main FastAPI application and delegates interpretation, case context,
intelligence, risk, and interventions to the canonical conversation service.
It does not require a separate Gradio server or port 7860. Number lookup and
other explicit actions continue to call FastAPI directly.

Start the backend using the normal FastAPI command, then configure the frontend
with the API URL and sign in to get a bearer token. The optional standalone Gradio UI in `app.py` is not part of the browser
Smart/Lite request path. SafeGuard's FastAPI server mounts the campaign composer
in-process, so the campaign feature does not require starting that standalone UI.

The Admin dashboard's **Data-driven education campaigns** section embeds the Gradio
campaign composer at `/campaign-studio` in the existing FastAPI process (normally
port `8000`). It prioritizes newly reported FIR tactics, then the most reported
tactics, generates tactic-based education copy, and saves drafts through the
existing campaign API. An administrator bearer token is required. Drafts remain in
the Admin dashboard for review and approval; generation never sends messages. FIR
counts distinguish reviewed and text-derived suggestions, and copy does not present
allegations as verified findings. With `GROQ_API_KEY`, copy is generated with Groq;
otherwise the composer uses safe tactic-specific templates.

Tests: `pytest` runs the unit tests (scoring, security, phone, schemas); the end-to-end auth and fraud tests need
`TEST_DATABASE_URL=postgresql+asyncpg://user:pass@localhost/safeguard_test` (they drop and recreate all tables).

## Authentication

**Smartphone users: phone OTP, then JWT**
1. `POST /v1/auth/otp/request {phone}` → 202 always (no account enumeration). Limited to 3 per phone / 10 min and 20 per IP / hour.
2. `POST /v1/auth/otp/verify {phone, code}` → `{access_token, refresh_token}`. Code is single-use, expires in 5 min, locks after 5 wrong guesses. The user is created on first successful login.
3. `Authorization: Bearer <access_token>` (15 min). `GET /v1/auth/me` returns the user.
4. `POST /v1/auth/refresh` rotates the refresh token (30 days, single use, held in a Redis allow-list). `POST /v1/auth/logout` revokes it.

Access tokens are stateless, so a suspended account is blocked on the next request (the user row is checked), but a
stolen access token stays usable until it expires (max 15 min).

**USSD / SMS gateways: HMAC**: requests carry `X-Gateway-Id`, `X-Timestamp` (unix seconds) and
`X-Signature = hex(HMAC-SHA256(secret, f"{timestamp}.{raw_body}"))`. Use the `GatewayDep` dependency on gateway routes.
Timestamps older than 5 minutes are rejected (replay protection). Secrets come from `GATEWAY_SECRETS`.

**Roles**: `user`, `reviewer`, `admin`. Protect routes with `Depends(require_roles(UserRole.REVIEWER))` (admin always passes).

## Errors

Every error has the same shape, including unhandled 500s:

```json
{"error": {"code": "invalid_otp", "message": "...", "details": null, "request_id": "..."}}
```
Raise `AppError` subclasses from services; clients can switch on `code`. The same id is returned in `X-Request-ID`
and appears on every log line for that request.

## Fraud Intelligence API

| Endpoint | Who | What |
|---|---|---|
| `POST /v1/reports` | user | Report a number (starts `pending`). 1 report per user per number per 24h, 20 per day. |
| `GET /v1/reports/mine`, `GET /v1/reports/{id}` | user | Own reports. Other people's reports return 404. |
| `GET /v1/reports?status=pending` | reviewer | Review queue, oldest first. |
| `POST /v1/reports/{id}/review` | reviewer | `approved` / `rejected` (final) or `needs_info` (can be followed by a final decision). `approved` may carry a `category_id`. Reviewers can't review their own reports. |
| `POST /v1/numbers/lookup` | user | Risk level, score, advice, categories and report counts (distinct reporters, never identities). Unknown numbers are not stored. |
| `GET/POST/PATCH/DELETE /v1/threats` | reviewer | List all indicators; create/edit/delete manual **blocklist** entries. **Allowlist** entries are admin-only. Automatic indicators are read-only. |
| `GET /v1/scam-categories`, `POST` | user / admin | Scam type catalogue. |
| `POST /v1/gateway/lookup`, `/v1/gateway/reports` | USSD/SMS gateway (HMAC) | Same actions for feature phones. The response includes `short_message` (max 160 chars). |

**Scoring** (`services/scoring.py`, pure and unit-tested): the score counts *distinct reporters*, so one person can't
inflate a number. Verified reporters weigh 0.6 and pending ones 0.15 in `1 - exp(-weight)`: 1 verified reporter is
medium, 2 high, 3 critical; it takes 3 pending reporters to reach medium. A manual blocklist entry sets a floor (and
wins over an allowlist entry), an allowlist entry forces low. Tune the weights and thresholds in that one file.

The automatic indicator is recomputed inside the same transaction as every report or review, under a per-number
Postgres advisory lock, so concurrent writes can't leave a stale score.

## Before production

- Replace `ConsoleSMSSender` (it logs OTPs) with a real SMS provider in `main.py`.
- Set `SECRET_KEY`; the app refuses to start in staging/production without a strong one.
- The `User` model gained a `role` column, so generate migrations after pulling this version.
