# SafeGuard backend

FastAPI + async SQLAlchemy (PostgreSQL) + Redis.

## Canonical intelligence boundary

FastAPI is the authoritative intelligence platform for every client surface:
Smart, Lite, SMS, calls, Admin, and the conversational assistant. Clients must
use the backend's case context, intelligence services, risk engine, and
intervention responses instead of implementing a separate risk decision.

`GET /v1/intelligence/capabilities` exposes the versioned boundary and the
currently authoritative capabilities. Typed message/SMS turns from Smart and
Lite pass through Gradio, which forwards them to this API. Number lookup and
other explicit actions call FastAPI directly.

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

## Run locally

```bash
make install
cp .env.example .env            # adjust database/Redis settings if needed
make infra-up
alembic upgrade head
make run                         # docs at /docs (disabled in staging/production)
```

`make test` runs the unit tests. The end-to-end auth and fraud tests need
`TEST_DATABASE_URL=postgresql+asyncpg://user:pass@localhost/safeguard_test`; they drop and recreate all tables.
Use `make check` for linting plus tests.

The migration chain is stored in `migrations/versions`. Generate a new
migration only after changing `app/models.py`, review the generated file, and
run `alembic upgrade head` against a disposable database before committing it.

## Local infrastructure

`docker compose up -d postgres redis` starts the development dependencies.
`docker compose down` stops them while retaining their named volumes. The
default development database and Redis URLs in `.env.example` match this
compose file.

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

## Partner Integration Layer

Administrators register a partner at `POST /api/v1/partners` or from the Admin
dashboard. `GET /v1/admin/partners` lists registered partners, and
`PATCH /v1/admin/partners/{id}/status` updates a partner's status.
The registration endpoint is admin-only. Each partner gets a generated HMAC
secret, encrypted in the database and returned only once at creation. Keep
`SECRET_KEY` stable across restarts so credentials and encrypted original
submissions remain decryptable. Apply migrations before use.

Partners submit data to `POST /api/v1/partners/identity`,
`POST /api/v1/partners/account`, or `POST /api/v1/partners/transactions` using
`X-Partner-Id` (the registered partner code), `X-Timestamp`, and
`X-Signature = hex(HMAC-SHA256(secret, f"{timestamp}.{raw_body}"))`. Timestamps
older than five minutes are rejected. Partner records are stored in `partners`,
`partner_identities`, `partner_accounts`, and `partner_transactions`. Each accepted
batch also stores an encrypted copy of its exact request and a normalized snapshot
in `partner_submissions` for audit and traceability. The batch endpoint
`POST /v1/partners/data` remains available for submitting all three record types
together. The existing API is also available under `/v1`.

Requests include a unique `submission_reference` and arrays named `identities`,
`accounts`, and `transactions`. References used for identity, phone, account, and
transaction joins are stored as keyed tokens. Send `phone_number` when providing a
phone in national or international format; SafeGuard normalizes and tokenizes it.
If sending `phone_number_reference` or `national_id_reference`, provide a protected
reference. Transaction account links are nullable when the account has not arrived
yet, while source references are retained for later resolution.

```json
{
  "submission_reference": "batch-2026-11-17-001",
  "schema_version": "1",
  "identities": [{
    "identity_reference": "customer-123",
    "national_id_reference": "partner-protected-reference",
    "phone_number": "0241234567",
    "verified_ownership": true,
    "verification_status": "verified"
  }],
  "accounts": [{
    "identity_reference": "customer-123",
    "account_identifier": "wallet-456",
    "account_type": "momo",
    "service_provider": "MTN",
    "account_status": "active",
    "ownership_reference": "customer-123"
  }],
  "transactions": [{
    "transaction_reference": "txn-789",
    "sender_account_reference": "wallet-456",
    "receiver_account_reference": "wallet-901",
    "amount": "25.00",
    "currency": "GHS",
    "balance": "120.00",
    "timestamp": "2026-11-17T10:30:00Z",
    "transaction_status": "successful"
  }]
}
```

**Roles**: `user`, `reviewer`, `admin`. Protect routes with `Depends(require_roles(UserRole.REVIEWER))` (admin always passes).

### Continuous awareness (opt-in)

Apply migrations with `alembic upgrade head`. Users manage consent through
`GET/PUT /v1/awareness/preferences`; structured conversation context is retained
only when `conversation_memory_enabled` is true. Turning it off deletes stored
conversation-context evidence and its Redis cache. The in-app awareness feed is
`GET /v1/awareness/inbox`.

Reviewers can draft a campaign tied to an active network signal with
`POST /v1/admin/awareness/campaigns`, then approve and send it with
`POST /v1/admin/awareness/campaigns/{campaign_id}/approve-and-send`. Supporting
admin routes: `GET /v1/admin/awareness/signals/{signal_id}/suggest` (data-driven
draft copy), `GET /v1/admin/awareness/signals/{signal_id}/audience-preview`,
`GET /v1/admin/awareness/outreach-stats`, and `GET /v1/admin/awareness/deliveries`.

Campaigns target users whose FIR reports are connected to the signal through a short
graph path. When a signal has no graph entity linkage, education campaigns may fall
back to recent reporters (90 days). Only users who opted into proactive education
are eligible. Delivery is limited to three campaigns per user in seven days.
High-risk alerts require a second reviewer. SMS bodies are truncated to 160
characters; in-app deliveries stay full length. Dashboard feedback metrics include
awareness deliveries and inbox reads from the last 30 days.

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
| `POST/GET /v1/cases`, `GET /v1/cases/{id}` | user | Create and inspect an owned fraud case with its evidence. |
| `POST /v1/cases/{id}/evidence`, `POST /v1/cases/{id}/close` | user | Add typed evidence or close a case. |
| `POST /v1/reports` | user | Report a number (starts `pending`). 1 report per user per number per 24h, 20 per day. |
| `GET /v1/reports/mine`, `GET /v1/reports/{id}` | user | Own reports. Other people's reports return 404. |
| `GET /v1/reports?status=pending` | reviewer | Review queue, oldest first. |
| `POST /v1/reports/{id}/review` | reviewer | `approved` / `rejected` (final) or `needs_info` (can be followed by a final decision). `approved` may carry a `category_id`. Reviewers can't review their own reports. |
| `POST /v1/numbers/lookup` | user | Risk level, score, advice, categories and report counts (distinct reporters, never identities). Optional message and transaction context can be supplied. Unknown numbers are not stored. |
| `POST /v1/transactions/assess` | user | Check a recipient, answer a social-engineering questionnaire, and receive a transfer recommendation. |
| `POST /v1/shield/analyze` | user | Analyze an SMS and return rule matches, AI classification, risk, and explanation. |
| `GET /v1/admin/dashboard` | admin | Live report, threat, protected-number, and 30-day risk-distribution metrics. |
| `GET /v1/admin/monitoring` | admin | Operational monitoring slice: dashboard risk mix, feedback effectiveness, recent cross-institution signals, and top graph entities (single call for the admin Monitoring view). |
| `GET/POST/PATCH/DELETE /v1/threats` | reviewer | List all indicators; create/edit/delete manual **blocklist** entries. **Allowlist** entries are admin-only. Automatic indicators are read-only. |
| `GET /v1/scam-categories`, `POST` | user / admin | Scam type catalogue. |
| `POST /v1/gateway/lookup`, `/v1/gateway/reports` | USSD/SMS gateway (HMAC) | Same actions for feature phones. The response includes `short_message` (max 160 chars). |
| `POST /v1/gateway/shield` | USSD/SMS gateway (HMAC) | Analyze an SMS for a feature-phone user and return a short warning. |
| `POST /v1/gateway/transaction-assess` | USSD/SMS gateway (HMAC) | Assess a transfer and return a short recommendation for USSD/SMS. |
| `POST /v1/communication/interpret` | user | Normalise a channel payload and return language, intent, stage, and privacy hints. |
| `POST /v1/network/number` | user | Return related fraud patterns and campaign fingerprints for a number without reporter identities. |
| `POST /v1/interventions/plan` | user | Convert a risk decision into a channel-specific safety action. |
| `POST/GET /v1/cases/{id}/feedback` | user | Record and inspect intervention adherence and real-world outcomes for an owned case. |
| `POST /v1/calls/analyze` | user | Analyse a user-activated call using optional, consented transcript text and return a privacy-safe intervention. |

## Shared cases and evidence

Cases provide a user-owned context for connecting related reports, number
lookups, Shield analyses, and transaction assessments. Create a case with
`POST /v1/cases`, then pass its `case_id` to those interaction requests. If a
case ID is omitted, report, Shield, and transaction flows create a new case
automatically and return its ID.

Case evidence is typed and auditable. Raw SMS bodies are not stored by the
Shield integration; it stores a content hash plus derived indicators. Use
`GET /v1/cases/{id}` to inspect evidence, `POST /v1/cases/{id}/evidence` to
append safe references or metadata, and `POST /v1/cases/{id}/close` to close a
case. Closed cases reject new evidence.

## Fraud Intelligence Repository (FIR)

FIR is the investigator-facing index across both report intake APIs:
`/v1/reports` and `/v1/community/reports`. Source submissions remain preserved;
the FIR record links them to reporter reference, case, evidence, extracted
entities, incident(s), risk history, reviewer decisions, and investigation
activity. Existing reports are indexed by migration `f17a2b3c4d5e`.

One report may link to several incidents, and an incident may aggregate reports
from both intake paths. The legacy `community_reports.incident_id` remains for
compatibility; FIR uses the many-to-many `report_incidents` relation. Incident
entities have explicit roles (`victim`, `suspect`, or `related`), and entity
links include confidence and verification status. Risk assessments and findings
are stored as timestamped records instead of replacing earlier results.

On both report intake paths, non-empty descriptions are passed through the
shared Fraud Intelligence Orchestrator. Selected pattern matches,
identity-analysis results, behaviour-model signals (including an explicit
no-match record), and the resulting risk snapshot are stored against the FIR
report and incident. Linking a report to another incident runs the same shared
analysis for that incident. Transaction-history behaviour stays attached to the
requesting user's transaction context; it is not attributed to a suspect or
incident.

Reviewer/admin endpoints:

| Endpoint | Purpose |
|---|---|
| `GET /v1/fir/reports`, `GET /v1/fir/reports/{id}` | Search reports and inspect evidence, entities, case, incidents, reviews, and assessment history. |
| `POST /v1/fir/reports/{id}/reanalyze` | Re-run shared intelligence for older reports or after model updates; findings are appended with provenance. |
| `POST /v1/fir/reports/{id}/entities` | Attach a provenance-tagged extracted entity. |
| `GET /v1/fir/incidents`, `GET /v1/fir/incidents/{id}` | Browse incidents and inspect reports, parties, findings, links, assessments, intelligence, and activity. |
| `POST /v1/fir/incidents` | Create an incident from a report; repeat for additional events described by that report. |
| `POST /v1/fir/reports/{report_id}/incidents/{incident_id}` | Link a report to an existing incident with confidence and reason. |
| `PATCH /v1/fir/incidents/{id}` | Update event details, status, outcome, or investigator assignment. |
| `POST /v1/fir/incidents/{id}/entities` | Add a victim, suspect, or related entity. |
| `POST /v1/fir/incidents/{id}/relationships` | Record a relationship between entities attached to the incident. |
| `POST /v1/fir/incidents/{id}/findings` | Add a pattern, behaviour, or other finding with confidence and provenance. |
| `POST /v1/fir/incidents/{id}/assessments`, `POST /v1/fir/incidents/{id}/activity` | Append an assessment snapshot or investigation action. |
| `POST /v1/fir/cases/{case_id}/assign` | Assign a case to a reviewer/admin investigator. |

FIR access is reviewer/admin only. Reporter identities are returned as internal
references; public intelligence endpoints continue to omit reporter identities.
Victim and suspect details are accessible to investigators and should be treated
as unverified unless their verification status says otherwise.

## ATLAS ecosystem map

ATLAS maps the **full SafeGuard intelligence ecosystem**: 38 scoped tables across FIR,
PDR, and shared layers (`community_entities`, `entity_relationships`, reports, cases,
partner accounts/transactions, identity resolution, assessments, etc.). Each **row** is a
graph node; edges come from **database foreign keys**, **multi-FK semantic links** on
junction tables, **`entity_relationships`**, **PDR→community_entities projection keys**,
and **partner-scoped transaction→account** references. `GET /v1/intelligence/layers/atlas/catalog`
lists scoped tables and row counts (not ancillary tables such as `users`). `GET /v1/intelligence/layers/atlas`
defaults to `coverage=ecosystem` when `table=all`: it loads **every row** in each scoped
table until `limit` (max node capacity, default 5000, up to 15000). Use `coverage=sample`
for legacy per-table paging. Filters (`source`, `type`, `query`, risk, verification, dates,
relationship type) narrow which rows enter the graph. `expand` and `path` continue to walk
provenance-preserving links from any node. Responses report `scoped_record_total`,
`ecosystem_complete`, and `truncated` when capacity is below total row count.

Communication Intelligence is the shared normalisation layer used by these
flows. It identifies the channel, normalises text and phone numbers, gives a
conservative intent/stage hint, and records privacy guidance. It does not make
a fraud decision and does not transcribe or retain call audio.

The Risk Assessment Engine is the only final decision-maker beneath lookup,
Shield, transaction, and gateway assessments. It combines phone reputation,
message and transaction signals, model/rule evidence, contradictions,
uncertainty, and provenance into one explainable decision. Its audit payload is
stored in `risk_assessments.signals` and case evidence.

Fraud Pattern Intelligence is available at `POST /v1/patterns/analyze` and is
also used by Shield. It returns taxonomy IDs, probabilities, model version,
evidence-backed explanations, counter-checks, and a privacy-safe campaign
fingerprint. The trained joblib artifact is optional; the deterministic
fallback keeps local development and API startup functional when ML artifacts
or optional ML dependencies are unavailable.

Behavioural Intelligence is applied to transaction assessments using recent
assessment history. It derives recipient familiarity, amount deviation,
assessment velocity, and mismatch signals, persists the snapshot in
`transaction_assessments.behavior_signals`, and feeds the bounded results into
the Risk Assessment Engine. These are contextual signals, not identity or
intent claims.

The pattern and behavioural joblib artifacts are loaded through the shared
`model_runtime` (`model-runtime.v1`). It loads `models/safeguard_pattern_classifier_v2.joblib`
and `models/safeguard_behaviour_classifier.joblib` once, records each artifact
and version in the intelligence evidence, and falls back safely if an artifact
or optional ML dependency is unavailable. Deployments can override the paths
with `SAFEGUARD_PATTERN_MODEL_PATH` and `SAFEGUARD_BEHAVIOUR_MODEL_PATH`.

Fraud Network Intelligence stores typed, confidence-weighted links between
numbers, reports, patterns, identity claims, cases, and campaign fingerprints.
The network lookup is intentionally privacy-preserving: it exposes related
intelligence, never the users who submitted reports. Network signals are fed
back into number lookup and the Risk Assessment Engine.

Identity Intelligence is available at `POST /v1/identity/analyze` and is used
by Shield. It detects organisation or authority claims, secret requests,
urgency, suspicious links, and configured official-domain matches. A matching
domain is only supporting evidence; it is never treated as proof that a
message or caller is legitimate.

The centralized Intervention Engine is the sole owner that converts risk into
an action such as informing,
requesting more context, independent verification, stopping and escalating, or
reporting an apparent loss. App responses include full guidance; USSD/SMS
responses use a bounded `short_message` of at most 160 characters.

Feedback closes the loop: users can record whether advice was followed,
transactions were cancelled or completed, fraud was confirmed, a loss was
reported, or a loss was prevented. Each outcome stores the risk/intervention
snapshot that produced it and becomes bounded evidence for later assessments
in the same case through the Risk Assessment Engine. False positives remain
calibration signals and do not silently lower current safety risk. Reviewer
decisions are recorded automatically against report-linked cases, and
administrators receive aggregate outcome and follow-rate metrics without
reporter identities.

Call Protection is explicitly user-triggered. Transcript analysis requires
consent, call audio is never recorded by the backend, and raw transcripts are
never stored; only derived signals and a content hash are retained.

**Scoring** (`services/scoring.py`, pure and unit-tested): the score counts *distinct reporters*, so one person can't
inflate a number. Verified reporters weigh 0.6 and pending ones 0.15 in `1 - exp(-weight)`: 1 verified reporter is
medium, 2 high, 3 critical; it takes 3 pending reporters to reach medium. The risk-assessment engine then adds
bounded evidence from message indicators (keywords, links, impersonation and urgency) and transaction context
(new recipient, amount/velocity anomalies and recipient mismatch) as additional hazard weight. A manual blocklist
entry sets a floor (and wins over an allowlist entry), while an allowlist entry forces low. Tune the weights and
thresholds in that one file.

Lookup responses include `assessment_components` and `risk_reasons`; persisted risk assessments retain the same
audit details in their `signals` field.

**Transaction Intelligence** checks the recipient through the same fraud intelligence lookup, scores social-engineering
signals such as OTP requests, urgency, secrecy, impersonation and remote-access requests, and returns one of three
actions: proceed with caution, verify the recipient, or stop and contact the bank.

The gateway endpoints are simulated USSD/SMS interfaces: send the same JSON over HTTP with `X-Gateway-Id`,
`X-Timestamp`, and `X-Signature` headers. Use `GATEWAY_SECRETS` in `.env` to configure the simulated `ussd` and
`sms` callers. All gateway responses keep `short_message` at or below 160 characters.

The automatic indicator is recomputed inside the same transaction as every report or review, under a per-number
Postgres advisory lock, so concurrent writes can't leave a stale score.

## SMS providers

Development defaults to `SMS_PROVIDER=console`, which logs OTPs and must never
be used in staging or production. Production requires `SMS_PROVIDER=http`,
`SMS_API_URL`, and `SMS_API_TOKEN`. The generic sender posts:

```json
{"to": "+233241234567", "message": "...", "sender_id": "SafeGuard"}
```

Adapt `HttpSMSSender` if the selected provider uses a different contract.

## Before production

- Configure a real SMS provider with `SMS_PROVIDER=http`; the app refuses the console sender in staging/production.
- Set `SECRET_KEY`; the app refuses to start in staging/production without a strong one.
- The `User` model gained a `role` column, so generate migrations after pulling this version.
