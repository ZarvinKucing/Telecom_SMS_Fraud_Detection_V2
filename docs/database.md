# Database (Phase 1 subset)

Tables: `ingest_batches` (unique `file_sha256`), `sms_records` (PK `message_id, received_time`, partitioned by `received_time`),
`rejected_rows`, `fraud_rules` (unique `rule_key, version`), `fraud_alerts` (unique `window_start, entity_type, entity_key, network`),
`risk_score_components`.

- Re-ingesting a file is a no-op (hash check), and overlapping `message_id`s are skipped by `ON CONFLICT DO NOTHING`.
- Re-running detection upserts alerts on the unique key instead of duplicating them.
- Message bodies are never stored. Destinations are stored in full; masking on read arrives with the API (Phase 2).
- Deviation from the blueprint ERD: `message_id` is `text`, not `uuid`, because the real feed's id format is unknown.
- Migrations `0001` and `0002` have been applied and verified on isolated PostgreSQL test databases.

## Phase 2 additions (migration `0002`)

Migration `0002` adds opaque user references, cases, case events/notes, an alert-to-case link, and a hash-chained audit log. Audit hashes detect row edits and middle-of-chain deletion, but cannot detect tail truncation or a full rewrite by a database owner/superuser. Audit details must use JSON-stable values.

### Production role setup

Use three distinct roles: a database owner used only for migrations, an API runtime role, and a worker runtime role. Create roles while connected to the PostgreSQL maintenance database as an administrator. Enter passwords with `psql`'s interactive `\password` command or your secret manager; do not put password literals in SQL, command history, `.env.example`, or source control.

```sql
CREATE ROLE fraud_migrator LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;
CREATE ROLE fraud_api LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;
CREATE ROLE fraud_worker LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;
```

In the interactive `psql` session, set each password without placing it in SQL history:

```text
\password fraud_migrator
\password fraud_api
\password fraud_worker
```

Create a new, empty application database owned by the migration role. Do not substitute an existing protected or production database in test commands.

```sql
CREATE DATABASE fraud_app OWNER fraud_migrator;
\connect fraud_app
REVOKE ALL ON DATABASE fraud_app FROM PUBLIC;
GRANT CONNECT ON DATABASE fraud_app TO fraud_api, fraud_worker;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO fraud_api, fraud_worker;
GRANT CREATE ON SCHEMA public TO fraud_migrator;
ALTER DEFAULT PRIVILEGES FOR ROLE fraud_migrator IN SCHEMA public
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE fraud_migrator IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM PUBLIC;
```

Run migrations as `fraud_migrator`, with an explicitly supplied owner URL and dotenv disabled. Inject the URL through the deployment secret manager or process environment; the runtime `.env` URL must never be reused for migrations.

```powershell
$env:PYTHON_DOTENV_DISABLED = "1"
# Inject the migration owner's DATABASE_URL from the secret manager here.
python -m alembic upgrade head
Remove-Item Env:DATABASE_URL
Remove-Item Env:PYTHON_DOTENV_DISABLED
```

### Runtime grants

Apply after migration as the database owner or administrator. The API receives no table ownership, DDL, delete, or truncate grants. Its column-level update permissions match the API handlers; the worker gets only the permissions used by `PostgresStore` and `run_cycle`.

```sql
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;

GRANT SELECT ON fraud_rules, fraud_alerts, risk_score_components, fraud_cases,
  case_events, case_notes, audit_log, ingest_batches TO fraud_api;
GRANT SELECT (sub, username, last_seen) ON user_refs TO fraud_api;
GRANT INSERT ON fraud_rules, fraud_cases, case_events, case_notes, audit_log,
  ingest_batches, sms_records, rejected_rows, user_refs TO fraud_api;
-- Postgres requires SELECT on the RETURNING column used by the idempotent SMS insert.
GRANT SELECT (message_id, received_time) ON sms_records, sms_records_default TO fraud_api;
GRANT UPDATE (username, last_seen) ON user_refs TO fraud_api;
GRANT UPDATE (case_id) ON fraud_alerts TO fraud_api;
GRANT UPDATE (status, assignee_sub, outcome_label, closed_at) ON fraud_cases TO fraud_api;
GRANT UPDATE (rows_loaded, rows_rejected, finished_at) ON ingest_batches TO fraud_api;
GRANT USAGE ON SEQUENCE fraud_rules_rule_pk_seq, fraud_cases_case_id_seq,
  case_events_id_seq, case_notes_id_seq, audit_log_audit_id_seq,
  rejected_rows_id_seq TO fraud_api;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM fraud_api;
-- Inserts routed through the current default partition require a direct child grant.
GRANT INSERT ON sms_records_default TO fraud_api;

GRANT SELECT ON sms_records, fraud_rules TO fraud_worker;
GRANT SELECT ON sms_records_default TO fraud_worker;
GRANT SELECT ON fraud_alerts TO fraud_worker;
GRANT INSERT ON fraud_rules, fraud_alerts TO fraud_worker;
GRANT UPDATE (risk_score, band) ON fraud_alerts TO fraud_worker;
GRANT SELECT (alert_id), DELETE, INSERT ON risk_score_components TO fraud_worker;
GRANT USAGE ON SEQUENCE fraud_rules_rule_pk_seq, fraud_alerts_alert_id_seq TO fraud_worker;
```

Verify these grants against the deployed schema and application queries after every migration. `backend.main:create` and the worker startup both fail closed if their runtime identity is a superuser, database/schema creator, owner/member of an owner role, broad writer, or can update/delete/truncate `audit_log`. The audit chain detects edits and middle-row deletion; it cannot detect tail truncation or a full rewrite by the schema owner or a superuser.

`sms_records_default` is the current Phase 1 default partition, so the API and worker need the explicit child grants above in addition to the parent grants. The API needs column-level `SELECT(message_id, received_time)` for the idempotent `INSERT ... ON CONFLICT ... RETURNING message_id`, and `SELECT(sub, username, last_seen)` for the identity upsert's conflict update. PostgreSQL requires table-level `SELECT` for the worker's alert upsert, so that role can read alert rows; the worker already reads SMS source records for detection. If additional partitions are introduced, grant the minimum required permissions on each new child partition as part of its creation/rotation procedure and verify effective privileges before routing traffic.

### Test database rules

The unit SQLRepo contract class is hard-pinned to database name exactly `fraud_test`. The opt-in PostgreSQL HTTP and isolated SQLRepo contract suites use their own exact database/role names declared in `tests/integration/`; never point destructive tests at `fraud_platform`, `fraud_test`, or the migration-review database. The integration test URLs are process-only inputs and are not stored in project files.
