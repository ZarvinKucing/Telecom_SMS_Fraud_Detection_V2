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
| PostgreSQL models, Alembic migration, `PostgresStore`, CLI `ingest`/`detect` | **Written, NOT executed** | no PostgreSQL or SQLAlchemy available where this was authored; only syntax-checked |
| Docker Compose (PostgreSQL only) | **Written, NOT executed** | |
| Off-hours and new-sender-burst rules, Isolation Forest anomaly signal | Proposed (Phase 1/2) | not implemented |
| FastAPI backend, permissions, cases, audit log | Proposed (Phase 2) | |
| Keycloak (OIDC, TOTP MFA, RBAC) | Proposed (Phase 3) | |
| OpenSearch monitoring, security detectors, incidents | Proposed (Phase 4) | |
| Streamlit dashboard | Proposed (Phase 5) | |
| CI, Bandit, dependency scanning, STRIDE model, TLS proxy | Proposed (Phase 6) | |

## Run it (no database needed)

```bash
pip install pandas numpy
python -m fraud_engine generate --out ./data/incoming --seed 2026
python -m fraud_engine analyze --input ./data/incoming
python -m unittest discover -s tests -t . -v      # or: pytest
```

`analyze` loads files into an in-memory store and prints scored alerts; results go to `./out/` (git-ignored).

With PostgreSQL (unverified path): copy `.env.example` to `.env`, fill in credentials, `docker compose up -d postgres`,
`alembic upgrade head`, then `python -m fraud_engine ingest` and `python -m fraud_engine detect --since ... --until ...`.

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

See `docs/phase0-repository-safety.md` for the data-handling decisions and the history-cleanup procedure.
