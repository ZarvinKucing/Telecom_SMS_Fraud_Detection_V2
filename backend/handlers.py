"""Route table. Every route declares its permission; nothing is reachable without one except /health."""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from backend.auth.permissions import Principal
from backend.core import PUBLIC, AppContext, Request, Router
from backend.errors import ApiError, NotFoundError
from backend.services import audit, cases
from backend.services.masking import contains_number, mask_entity
from backend.validation import Checker, finish_all, paging
from fraud_engine.ingest import ingest_file
from fraud_engine.rules import FraudRule

router = Router()
BANDS = ("low", "medium", "high", "critical")
ENTITY_TYPES = ("destination", "sender", "sender_destination")
_FILE_NAME = r"[A-Za-z0-9][A-Za-z0-9._\-]{0,100}\.csv"


def _sub(principal: Principal | None) -> str:
    assert principal is not None
    return principal.sub


def _present_alert(alert: dict[str, Any], unmask: bool = False) -> dict[str, Any]:
    out = dict(alert)
    if not unmask:
        out["entity_key"] = mask_entity(alert["entity_type"], alert["entity_key"])
    return out


@router.add("GET", "/health", PUBLIC, summary="Liveness probe")
def health(ctx: AppContext, p: Principal | None, req: Request, d: dict[str, Any]) -> tuple[int, Any]:
    return 200, {"status": "ok"}


@router.add("GET", "/fraud/summary", "fraud:summary:read", summary="Aggregate fraud counts (no identifiers)")
def summary(ctx: AppContext, p: Principal | None, req: Request, d: dict[str, Any]) -> tuple[int, Any]:
    return 200, {**ctx.repo.alert_summary(), "cases_by_status": ctx.repo.case_status_counts()}


def _v_alert_list(params: Any, query: Any, body: Any) -> dict[str, Any]:
    q = Checker(query, text=True, where="query")
    q.enum("band", BANDS, required=False)
    q.enum("entity_type", ENTITY_TYPES, required=False)
    q.string("network", max_len=64, pattern=r"[A-Za-z0-9_.\-]+", required=False)
    paging(q)
    return finish_all(q)


@router.add("GET", "/fraud/alerts", "fraud:alert:read", validator=_v_alert_list, summary="List alerts (masked)")
def list_alerts(ctx: AppContext, p: Principal | None, req: Request, d: dict[str, Any]) -> tuple[int, Any]:
    rows, total = ctx.repo.list_alerts(band=d["band"], network=d["network"], entity_type=d["entity_type"],
                                       limit=d["limit"], offset=d["offset"])
    return 200, {"total": total, "limit": d["limit"], "offset": d["offset"],
                 "items": [_present_alert(r) for r in rows]}


def _v_alert_get(params: Any, query: Any, body: Any) -> dict[str, Any]:
    pc = Checker(params, text=True, where="path")
    pc.integer("alert_id", lo=1, hi=10**15)
    q = Checker(query, text=True, where="query")
    q.boolean("unmask", default=False)
    return finish_all(pc, q)


@router.add("GET", "/fraud/alerts/{alert_id}", "fraud:alert:read", validator=_v_alert_get,
            extra_permission=lambda d: "fraud:msisdn:unmask" if d.get("unmask") else None,
            summary="Alert detail with score components; ?unmask=true needs fraud:msisdn:unmask and is audited")
def get_alert(ctx: AppContext, p: Principal | None, req: Request, d: dict[str, Any]) -> tuple[int, Any]:
    alert = ctx.repo.get_alert(d["alert_id"])
    if alert is None:
        raise NotFoundError(f"alert {d['alert_id']}")
    if d["unmask"]:
        audit.record(ctx.repo, ctx.clock, _sub(p), "msisdn.unmask", "alert", d["alert_id"],
                     source_ip=req.client_ip,
                     details={"numbers": contains_number(alert["entity_type"]),
                              "entity_type": alert["entity_type"]})
    return 200, _present_alert(alert, unmask=d["unmask"])


@router.add("GET", "/fraud/rules", "fraud:rules:read", summary="Current version of every rule")
def list_rules(ctx: AppContext, p: Principal | None, req: Request, d: dict[str, Any]) -> tuple[int, Any]:
    return 200, {"items": ctx.repo.list_rules()}


def _v_rule_put(params: Any, query: Any, body: Any) -> dict[str, Any]:
    pc = Checker(params, text=True, where="path")
    pc.string("rule_key", max_len=64, pattern=r"[a-z0-9_]{1,64}")
    b = Checker(body)
    b.number_map("params", max_items=10)
    b.number("weight", lo=0.0, hi=1.0)
    b.boolean("enabled", default=True)
    return finish_all(pc, b)


@router.add("PUT", "/fraud/rules/{rule_key}", "fraud:rules:write", validator=_v_rule_put, writes=True,
            summary="Create a new version of a rule (old versions are kept)")
def put_rule(ctx: AppContext, p: Principal | None, req: Request, d: dict[str, Any]) -> tuple[int, Any]:
    current = ctx.repo.get_latest_rule(d["rule_key"])
    if current is None:
        raise NotFoundError(f"rule {d['rule_key']}")
    try:  # reuse the engine's own validation so the API cannot store a rule the engine would reject
        FraudRule(d["rule_key"], current["rule_type"], d["params"], d["weight"], enabled=d["enabled"])
    except ValueError as exc:
        raise ApiError(422, "validation_error", str(exc)) from exc
    new = ctx.repo.add_rule_version(d["rule_key"], current["rule_type"], d["params"], d["weight"], d["enabled"])
    audit.record(ctx.repo, ctx.clock, _sub(p), "rule.update", "rule", d["rule_key"], source_ip=req.client_ip,
                 details={"from_version": current["version"], "to_version": new["version"],
                          "old": {"params": current["params"], "weight": current["weight"],
                                  "enabled": current["enabled"]},
                          "new": {"params": d["params"], "weight": d["weight"], "enabled": d["enabled"]}})
    return 200, new


def _v_ingest(params: Any, query: Any, body: Any) -> dict[str, Any]:
    b = Checker(body)
    b.string("file_name", max_len=105, pattern=_FILE_NAME)
    b.string("content", max_len=50_000_000, min_len=1)
    return finish_all(b)


@router.add("POST", "/fraud/ingest", "sms:ingest", validator=_v_ingest, writes=True,
            summary="Ingest one CDR CSV (idempotent by content hash)")
def ingest(ctx: AppContext, p: Principal | None, req: Request, d: dict[str, Any]) -> tuple[int, Any]:
    raw = d["content"].encode()
    if len(raw) > ctx.max_ingest_bytes:
        raise ApiError(413, "payload_too_large", f"limit is {ctx.max_ingest_bytes} bytes")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "inbox" / d["file_name"]  # name is pattern-validated: no separators or '..'
        path.parent.mkdir()
        path.write_bytes(raw)
        result = ingest_file(path, ctx.store, Path(tmp) / "processed", ctx.source_tz)
    audit.record(ctx.repo, ctx.clock, _sub(p), "ingest.upload", "file", d["file_name"], source_ip=req.client_ip,
                 outcome="success" if result.status in {"loaded", "skipped_duplicate_file"} else "failure",
                 details={"status": result.status, "rows_read": result.rows_read,
                          "rows_loaded": result.rows_loaded, "rows_rejected": result.rows_rejected})
    body = {"file_name": result.file_name, "status": result.status, "rows_read": result.rows_read,
            "rows_loaded": result.rows_loaded, "rows_rejected": result.rows_rejected}
    if result.status == "invalid_schema":
        return 422, {**body, "error": "invalid_schema", "message": result.error}
    if result.status == "failed":
        return 502, {**body, "error": "ingest_failed"}
    return 200, body


def _v_case_create(params: Any, query: Any, body: Any) -> dict[str, Any]:
    b = Checker(body)
    b.int_list("alert_ids", min_items=1, max_items=50, lo=1, hi=10**15)
    b.enum("priority", cases.PRIORITIES, required=False)
    return finish_all(b)


@router.add("POST", "/fraud/cases", "fraud:case:write", validator=_v_case_create, writes=True,
            summary="Open a case from one or more alerts")
def create_case(ctx: AppContext, p: Principal | None, req: Request, d: dict[str, Any]) -> tuple[int, Any]:
    return 201, cases.create_case(ctx.repo, ctx.clock, _sub(p), req.client_ip, d["alert_ids"], d["priority"])


def _v_case_list(params: Any, query: Any, body: Any) -> dict[str, Any]:
    q = Checker(query, text=True, where="query")
    q.enum("status", cases.STATUSES, required=False)
    paging(q)
    return finish_all(q)


@router.add("GET", "/fraud/cases", "fraud:case:read", validator=_v_case_list, summary="List cases")
def list_cases(ctx: AppContext, p: Principal | None, req: Request, d: dict[str, Any]) -> tuple[int, Any]:
    rows, total = ctx.repo.list_cases(status=d["status"], limit=d["limit"], offset=d["offset"])
    return 200, {"total": total, "limit": d["limit"], "offset": d["offset"], "items": rows}


def _case_id(params: Any) -> Checker:
    c = Checker(params, text=True, where="path")
    c.integer("case_id", lo=1, hi=10**15)
    return c


def _v_case_get(params: Any, query: Any, body: Any) -> dict[str, Any]:
    return finish_all(_case_id(params), Checker(query, text=True, where="query"))


@router.add("GET", "/fraud/cases/{case_id}", "fraud:case:read", validator=_v_case_get,
            summary="Case with alerts, events and notes")
def get_case(ctx: AppContext, p: Principal | None, req: Request, d: dict[str, Any]) -> tuple[int, Any]:
    case = ctx.repo.get_case(d["case_id"])
    if case is None:
        raise NotFoundError(f"case {d['case_id']}")
    return 200, case


def _v_transition(params: Any, query: Any, body: Any) -> dict[str, Any]:
    b = Checker(body)
    b.enum("to_status", cases.STATUSES)
    b.string("reason", max_len=500, required=False)
    return finish_all(_case_id(params), b)


@router.add("POST", "/fraud/cases/{case_id}/transition", "fraud:case:write", validator=_v_transition,
            writes=True, summary="Move a case along the workflow")
def transition(ctx: AppContext, p: Principal | None, req: Request, d: dict[str, Any]) -> tuple[int, Any]:
    return 200, cases.transition_case(ctx.repo, ctx.clock, _sub(p), req.client_ip, d["case_id"],
                                      d["to_status"], d["reason"])


def _v_reopen(params: Any, query: Any, body: Any) -> dict[str, Any]:
    b = Checker(body)
    b.string("reason", min_len=10, max_len=500)
    return finish_all(_case_id(params), b)


@router.add("POST", "/fraud/cases/{case_id}/reopen", "fraud:case:write", validator=_v_reopen, writes=True,
            summary="Reopen a closed case (reason required)")
def reopen(ctx: AppContext, p: Principal | None, req: Request, d: dict[str, Any]) -> tuple[int, Any]:
    return 200, cases.reopen_case(ctx.repo, ctx.clock, _sub(p), req.client_ip, d["case_id"], d["reason"])


def _v_note(params: Any, query: Any, body: Any) -> dict[str, Any]:
    b = Checker(body)
    b.string("body", min_len=1, max_len=2000)
    return finish_all(_case_id(params), b)


@router.add("POST", "/fraud/cases/{case_id}/notes", "fraud:case:write", validator=_v_note, writes=True,
            summary="Add an analyst note")
def add_note(ctx: AppContext, p: Principal | None, req: Request, d: dict[str, Any]) -> tuple[int, Any]:
    return 201, cases.add_note(ctx.repo, ctx.clock, _sub(p), req.client_ip, d["case_id"], d["body"])


def _v_audit_list(params: Any, query: Any, body: Any) -> dict[str, Any]:
    q = Checker(query, text=True, where="query")
    paging(q)
    return finish_all(q)


@router.add("GET", "/audit", "audit:read", validator=_v_audit_list, summary="Audit trail, newest first")
def list_audit(ctx: AppContext, p: Principal | None, req: Request, d: dict[str, Any]) -> tuple[int, Any]:
    rows, total = ctx.repo.list_audit(limit=d["limit"], offset=d["offset"])
    return 200, {"total": total, "limit": d["limit"], "offset": d["offset"], "items": rows}


@router.add("GET", "/audit/verify", "audit:read", summary="Verify the audit hash chain")
def verify_audit(ctx: AppContext, p: Principal | None, req: Request, d: dict[str, Any]) -> tuple[int, Any]:
    r = audit.verify_chain(ctx.repo.iter_audit())
    return 200, {"ok": r.ok, "rows": r.rows, "first_bad_audit_id": r.first_bad_audit_id, "reason": r.reason}
