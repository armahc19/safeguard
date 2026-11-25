# SafeGuard API operations

This service is intended to run behind a TLS-terminating reverse proxy or load
balancer. The application container listens on port `8000` and runs as the
unprivileged `safeguard` user.

## Release checklist

1. Build and scan the image from the project root: `docker build -f backend/Dockerfile -t safeguard-api:release .`.
2. Set secrets through the deployment secret manager, never in the image or
   repository. At minimum set a random 32+ character `SECRET_KEY`, production
   `DATABASE_URL`, `REDIS_URL`, explicit `TRUSTED_HOSTS`, `CORS_ORIGINS`, and a
   non-console SMS provider.
3. Run `alembic upgrade head` as a release/migration job using the same image
   and database credentials.
4. Start the API with the image command. Keep at least one previous image
   available for rollback, but do not roll back application code across an
   irreversible database migration without a tested database plan.
5. Verify `/health/live` and `/health/ready` from the deployment environment.

## Probes and monitoring

- `/health/live` only indicates that the process is running.
- `/health/ready` checks PostgreSQL and Redis and should control traffic
  admission. A failed readiness check should remove the instance from service.
- Logs are structured in production and include a request ID. Monitor 5xx
  responses, readiness failures, request-rate-limit responses, latency, and
  database/Redis saturation.
- The service deliberately does not log OTP values, raw call transcripts, or
  raw call audio. Keep those data-handling guarantees when adding exporters.

## Data protection

- Back up PostgreSQL on a tested schedule and perform restore drills.
- Treat Redis as operational/transient state for OTPs, rate limits, and cache;
  use an appropriate persistence and failover policy for the deployment.
- Protect gateway credentials and SMS credentials with secret-manager rotation.
- Keep TLS, firewall, and reverse-proxy request limits enabled at the edge as
  a second layer of protection.

## Continuous Awareness agent and scheduler

The recurring worker runs inside the existing FastAPI process; it does not
start another server. It checks for due, opted-in subscribers every five
minutes by default in production. Development and test environments poll once
a minute so the one-minute simulation can be observed. When subscribers are
due, it invokes the same Gradio awareness copy generator, saves an education
campaign draft tied to the current tactic/signal, and associates the due
subscribers. The worker never sends the message; a reviewer must approve it.
Approval sends to live SMS subscribers through the configured provider. A
one-minute development test subscriber receives a simulated SMS interaction
that appears in SafeGuard Lite instead. Configure
`AWARENESS_SCHEDULER_ENABLED=false` to disable it, or set
`AWARENESS_SCHEDULER_INTERVAL_SECONDS` to change the production interval. Apply
database migrations and configure an HTTP SMS provider for carrier delivery.

The one-shot command below remains available as an optional fallback or for an
operator-triggered draft generation:

```cron
*/5 * * * * cd /home/scriptgad/Documents/Projects/sec/backend && /home/scriptgad/Documents/Projects/sec/.venv/bin/python -m app.services.awareness_scheduler >> /tmp/safeguard-awareness.log 2>&1
```

For a local one-time run, execute the command after `cd backend`. In this
workspace, run migrations with `../.venv/bin/alembic upgrade head`. The Admin
Dashboard's **Generate due drafts now** button invokes the same worker and asks
for confirmation. With a console-only SMS adapter, normal scheduled subscribers
are deferred, while one-minute test subscribers can still exercise the
approval-to-Lite simulation. Voice-only preferences and unsupported languages
remain deferred until a supported delivery path/content exists.
