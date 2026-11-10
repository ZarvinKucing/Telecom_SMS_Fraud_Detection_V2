# Integrated Fraud Analytics & Cybersecurity Management Platform with IAM

A rebuild of an internship project (SMS-pumping detection on telecom CDR data) into a modular platform:
fraud analytics, security monitoring and identity management as three separate planes.
The original idea is preserved: detect abnormal SMS **traffic patterns** (not message content) using hourly-window rules.

**All data in this repository is synthetic.** Destinations use the fictitious prefix `99912`, clients and senders are invented labels,
and the generator never produces message content. No operational data, credentials, or internal diagrams from the original work are included.

## Status: Implemented vs Proposed

| Area | Status | Evidence |
|---|---|---|
| Synthetic CDR generator with injected fraud + ground truth | **Implemented** | `tests/unit/test_generator.py` |
| Validation / normalization (UTC, address cleanup, reject reasons, message body dropped) | **Implemented** | `tests/unit/test_normalize.py` |
| Idempotent, failure-safe ingest (file moved only after commit) | **Implemented** against an in-memory store | `tests/unit/test_ingest.py` |
| Hourly windows; rules: repeated destination, per sender, spiking sender | **Implemented** | `tests/unit/test_rules.py` |
| Explainable risk score with stored components and bands | **Implemented** | `tests/unit/test_scoring.py` |
| CLI (`generate`, `analyze`) | **Implemented** (offline mode, no DB) | manual run, see below |
| PostgreSQL models, Alembic migrations 0001/0002, `PostgresStore`, CLI `ingest`/`detect` | **Implemented and verified on disposable PostgreSQL databases** | `tests/integration/`, migration verification |
| Isolation Forest corroboration and detection worker | **Implemented** | `tests/unit/test_anomaly_and_worker.py` |
| RS256 JWT authentication and server-side RBAC | **Implemented** | `tests/unit/test_permissions_and_tokens.py`, `tests/unit/test_api.py` |
| FastAPI process, HTTP transport, fraud alert API and masking | **Implemented and smoke-tested** | `backend/main.py`, `tests/integration/`, `docs/api.md` |
| Case lifecycle, versioned rules, hash-chained audit trail | **Implemented** | `tests/unit/test_cases.py`, `tests/unit/test_api.py` |
| SQL repository contract | **Implemented and verified on a disposable PostgreSQL database** | `tests/integration/test_sql_repo_contract.py` |
| Runtime/migration/worker PostgreSQL roles | **Least-privilege grants documented and verified on a disposable database** | `docs/database.md`, `backend/db_roles.py` |
| Docker Compose (PostgreSQL only) | **Configured for local PostgreSQL** | `docker-compose.yml` |
| Off-hours and new-sender-burst rules | Proposed | not implemented |
| Keycloak (OIDC, TOTP MFA, RBAC) | Proposed (Phase 3) | |
| OpenSearch monitoring, security detectors, incidents | Proposed (Phase 4) | |
| Streamlit dashboard | Proposed (Phase 5) | |
| CI, Bandit, dependency scanning, STRIDE model, TLS proxy | Proposed (Phase 6) | |

## Phase 2 handoff status

**Phase 2 implementation is complete.** The following PostgreSQL-backed results were previously verified on the dedicated test databases:

- Repository contract: **30 passed, 7 subtests passed**.
- PostgreSQL HTTP integration: **2 passed**.

**Unresolved verification caveat:** a DB-enabled full-suite run reported **201 passed, 14 skipped, 18 subtests passed, 1 failed** at
`tests/unit/test_cases.py::WorkflowTests::test_every_illegal_transition_is_409_and_changes_nothing` (expected HTTP 200, received 401).
Subsequent isolated, module, and non-DB full-suite runs passed; the root cause remains unknown and the DB-enabled failure has not been reproduced since.
Do not treat those later runs as proof that the DB-enabled failure is fixed. On the next DB-enabled full-suite run, if it recurs, capture only the structured JWT rejection `reason` field; do not capture tokens, keys, credentials, or connection URLs.

## Local setup

```bash
python -m venv .venv
.venv/Scripts/Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
```

Fill `.env` locally using a new empty development database name and your secret manager or secure local credential process. The example config creates only the PostgreSQL bootstrap database `postgres`; it does not select an application or production database. Never commit `.env`.

Start the local PostgreSQL service and create the migration-owner, API, and worker roles using [docs/database.md](docs/database.md):

```powershell
docker compose up -d postgres
```

Apply migrations using the migration-owner URL from a secure environment variable. Set `PYTHON_DOTENV_DISABLED=1` for this command so the API runtime URL from `.env` cannot be selected accidentally. Then set `DATABASE_URL` in the API process environment to the `fraud_api` URL and start the backend:

```powershell
$env:PYTHON_DOTENV_DISABLED = "1"
# Inject migration-owner DATABASE_URL from your secret manager, then:
python -m alembic upgrade head
Remove-Item Env:DATABASE_URL
Remove-Item Env:PYTHON_DOTENV_DISABLED

# Inject the fraud_api DATABASE_URL and RS256 JWT settings into the API process.
python -m uvicorn backend.main:create --factory --host 127.0.0.1 --port 8000
```

`backend.main:create` loads `.env` for local runs when variables are not already present, validates the RSA key, checks the runtime database role, seeds missing default rules, and disposes its database pool on shutdown. Verify local liveness with `Invoke-RestMethod http://127.0.0.1:8000/health`. The factory refuses to start with an owner, superuser, DDL-capable, or audit-mutating runtime role. This phase uses configured RS256 verification; it does not include Keycloak/OIDC integration or production deployment.

The OpenAPI schema endpoint is disabled by default. For local development, set `APP_ENV=development` and `OPENAPI_PUBLIC=true` in your local environment to expose `/openapi.json`; configuration rejects public schema exposure in staging or production. Leave `OPENAPI_PUBLIC=false` for deployed environments.

The offline example remains available:

```powershell
python -m fraud_engine generate --out ./data/incoming --seed 2026
python -m fraud_engine analyze --input ./data/incoming
```

`analyze` loads files into an in-memory store and writes results under `./out/` (git-ignored). Unit and integration suites are run with `python -m pytest`; PostgreSQL integration test URLs are opt-in and restricted to the exact disposable database names declared by those tests.

## How detection works

Records are grouped into UTC hourly windows. Illustrative default thresholds (not production values):

- **repeated_destination**: more than 25 messages to one destination in an hour (per network).
- **repeated_destination_per_sender**: same, per sender and destination. Kept for attribution; on its own it adds no detection beyond the first rule.
- **spiking_sender**: sender volume above 5x its own median for the same hour of day over the previous 7 days, with a floor and a minimum volume. Senders with under 3 days of history are skipped (a future new-sender rule would cover them).

Each hit has a weight `w` and severity `s` (0.5 just past threshold, 1.0 at twice the threshold). Hits on the same entity combine as
`S = 100 * (1 - prod(1 - w_i * s_i))`; components and rule versions are kept so every alert is explainable.

## Known limitations

- Thresholds, weights and the severity curve are untuned defaults. The synthetic generator is simple, so "no false positives on clean data" only shows the rules are sound on that data, not on real traffic.
- The synthetic schema (11 columns) reflects the *shape* of a CDR feed. The original 50-column layout was not inspected; add header mappings in `fraud_engine/normalize.py` (`COLUMN_ALIASES`) when onboarding a real feed.
- `sms_records` is partitioned with a DEFAULT partition only; monthly partitions are not yet automated.
- Loading uses chunked `INSERT ... ON CONFLICT DO NOTHING`, not the staging-table `COPY` from the blueprint.
- PostgreSQL behavior was exercised on isolated test databases; those tests do not validate production capacity,
  deployment networking, backup/restore, TLS termination, or operational monitoring.
- The audit chain detects edits and middle-row deletion, but not tail truncation or a complete rewrite by a database
  owner/superuser. API and worker roles must be separate from the schema owner; see `docs/database.md`.
- Case authorization is role-wide: any fraud analyst with case read/write permission can list, view, and change every case. There is no assignment-based, tenant, or per-case object scope; deploy only where all fraud analysts share one trust boundary until that policy is added.
- Identifier masking is enforced at the HTTP response layer. The API and worker database credentials can still read raw identifiers, so protect database credentials and network access accordingly.
- The anomaly detector is a secondary signal only. Its synthetic evaluation is small and does not establish
  performance on real traffic; see `docs/anomaly-evaluation.md`.

See `docs/phase0-repository-safety.md` for the data-handling decisions and the history-cleanup procedure.
