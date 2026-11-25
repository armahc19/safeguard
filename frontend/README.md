# SafeGuard web simulations

This is a dependency-free browser frontend for testing the three product surfaces:

- **SafeGuard Smart** — Android-style SMS Shield and transaction checks.
- **SafeGuard Lite** — simulated USSD/SMS feature-phone flows.
- **Administration** — review queue, risk distribution and operational metrics.
- **Intelligence layers** — FIR/PDR counts, fused entity risk, graph signals and partner alert status.

ATLAS is the investigator-facing ecosystem graph. Search can jump to matching
source rows; repository, record table, risk, verification, date, and relationship
filters narrow the view. Select a node to expand its neighborhood, or set start
and end records to trace a bounded path with per-link provenance.

## Run

From this directory, serve the files with any static HTTP server:

```bash
python -m http.server 5173
```

Open <http://localhost:5173>.

The UI starts in live API mode. Configure the settings gear before using it:

- API URL: `http://localhost:8000/v1`
- Bearer token: an access token from `/v1/auth/otp/verify`
- Keep demo mode disabled for the unified product flow. Demo mode is an explicit
  offline preview only and does not represent backend fraud decisions.

The live Smart flows use FastAPI for transaction assessment, call assessment,
reports, and shared case/intelligence actions. Lite uses FastAPI for phone
number lookup, suspicious SMS analysis, reports, and report history; it carries
one gateway case ID across the session. Production gateway requests must
include the documented HMAC headers. All direct actions consume backend
intelligence, risk, intervention, and case-context contracts.

For a local end-to-end intelligence demo, apply the backend migrations, start
PostgreSQL/Redis and the API, then run `python scripts/seed_intelligence_demo.py`
from `backend`. It creates a development admin login and clearly named demo
FIR/PDR records. Sign in with `SAFEGUARD_DEMO_ADMIN_PHONE` (default
`+233200000001`) using the OTP shown by the backend, switch to Admin, and select
**Populate demo data** to add or refresh the sample rows. Seeding is restricted
to development/test environments.

Pasted SMS/message analysis uses FastAPI's in-process conversation adapter at
`/v1/conversation/adapter-turn`. The adapter delegates interpretation, risk,
and intervention to the canonical `/v1/conversation/turn` service. Lite no
longer needs a separate Gradio server or port 7860.
