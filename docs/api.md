# API

All API endpoints except `/health` require a Bearer JWT (RS256). `/openapi.json` is mounted only when
`OPENAPI_PUBLIC=true`, which is allowed only with `APP_ENV=development` or `APP_ENV=test`. Both settings
default safely to production behavior when omitted: the schema endpoint is not mounted. Do not enable
public schema publishing in staging or production. Order of checks is fixed:
The HTTP adapter first enforces the request-size limit and parses JSON, so an oversized or malformed
body can receive 413 or 400 before authentication. For a well-formed request, checks proceed as
authenticate (401) → permission (403, audited) → semantic validation (422) → handler in one transaction.
State-changing routes must write an audit row or they are rolled back with a 500.
When enabled for local development or tests, the OpenAPI document is generated from the same route table
and documents its own public endpoint.

| Method | Path | Permission | Roles | Audited | Summary |
|---|---|---|---|---|---|
| GET | `/health` | `public` | anyone | no | Liveness probe |
| GET | `/fraud/summary` | `fraud:summary:read` | administrator, fraud_analyst, viewer | no | Aggregate fraud counts (no identifiers) |
| GET | `/fraud/alerts` | `fraud:alert:read` | fraud_analyst | no | List alerts (masked) |
| GET | `/fraud/alerts/{alert_id}` | `fraud:alert:read` | fraud_analyst | no | Alert detail with score components; ?unmask=true needs fraud:msisdn:unmask and is audited |
| GET | `/fraud/rules` | `fraud:rules:read` | administrator, fraud_analyst | no | Current version of every rule |
| PUT | `/fraud/rules/{rule_key}` | `fraud:rules:write` | fraud_analyst | yes | Create a new version of a rule (old versions are kept) |
| POST | `/fraud/ingest` | `sms:ingest` | fraud_analyst | yes | Ingest one CDR CSV (idempotent by content hash) |
| POST | `/fraud/cases` | `fraud:case:write` | fraud_analyst | yes | Open a case from one or more alerts |
| GET | `/fraud/cases` | `fraud:case:read` | fraud_analyst | no | List cases |
| GET | `/fraud/cases/{case_id}` | `fraud:case:read` | fraud_analyst | no | Case with alerts, events and notes |
| POST | `/fraud/cases/{case_id}/transition` | `fraud:case:write` | fraud_analyst | yes | Move a case along the workflow |
| POST | `/fraud/cases/{case_id}/reopen` | `fraud:case:write` | fraud_analyst | yes | Reopen a closed case (reason required) |
| POST | `/fraud/cases/{case_id}/notes` | `fraud:case:write` | fraud_analyst | yes | Add an analyst note |
| GET | `/audit` | `audit:read` | administrator, security_analyst | no | Audit trail, newest first |
| GET | `/audit/verify` | `audit:read` | administrator, security_analyst | no | Verify the audit hash chain |

## Behaviour worth knowing
- Case permissions are role-wide: every fraud analyst with the case read/write permission can access and change every case. There is no tenant, assignment, or per-case object authorization in this phase.
- Destination numbers are returned masked (`99912*****01`). `GET /fraud/alerts/{id}?unmask=true` needs
  `fraud:msisdn:unmask` as well, and writes a `msisdn.unmask` audit row (the audit row never stores the number).
- Masking is an API presentation control; runtime database roles can access raw identifiers as required by ingestion and detection. Restrict database credentials and network access.
- Permission denials (403) are written to the audit log. Failed or missing tokens (401) are logged and sent to the
  security-event hook only, so unauthenticated traffic cannot flood the audit table; Phase 4 consumes the hook.
- Case workflow: `New → Triaged → Investigating ⇄ NeedsInfo`, `Investigating → ConfirmedFraud | FalsePositive → Closed`.
  Closing sets the outcome label from the state it closed from. A closed case can only be reopened through
  `/reopen` with a reason (≥10 characters).
- Rules are versioned: `PUT` creates a new version and keeps the old ones; the worker records which version
  produced each score component.
- Ingest takes JSON `{file_name, content}` (CSV text) for now; multipart upload is not implemented.
- Validation is strict hand-written code (unknown fields are rejected), not Pydantic. See `backend/app.py`.
