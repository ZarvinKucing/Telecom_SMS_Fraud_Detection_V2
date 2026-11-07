# Database (Phase 1 subset)

Tables: `ingest_batches` (unique `file_sha256`), `sms_records` (PK `message_id, received_time`, partitioned by `received_time`),
`rejected_rows`, `fraud_rules` (unique `rule_key, version`), `fraud_alerts` (unique `window_start, entity_type, entity_key, network`),
`risk_score_components`.

- Re-ingesting a file is a no-op (hash check), and overlapping `message_id`s are skipped by `ON CONFLICT DO NOTHING`.
- Re-running detection upserts alerts on the unique key instead of duplicating them.
- Message bodies are never stored. Destinations are stored in full; masking on read arrives with the API (Phase 2).
- Deviation from the blueprint ERD: `message_id` is `text`, not `uuid`, because the real feed's id format is unknown.
- Status: migration `0001` and models are unexecuted; run `alembic upgrade head` against PostgreSQL 16 to verify.
