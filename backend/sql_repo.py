"""PostgreSQL Repo (SQLAlchemy Core, parameterized SQL only).

The shared repository contract is exercised against this class by the opt-in PostgreSQL integration
tests as well as against MemoryRepo by the regular unit suite.
"""
from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime
from typing import Any

import pandas as pd
from sqlalchemy import Connection, Engine, text

from backend.errors import ConflictError, NotFoundError
from backend.services import audit
from fraud_engine.rules import RuleMetadata

Row = dict[str, Any]
BANDS = ("low", "medium", "high", "critical")
_AUDIT_LOCK_KEY = 727001  # serializes audit appends so the hash chain has one writer at a time
_RULE_SEED_LOCK_KEY = 727002  # serializes first-start default rule seeding across API and worker
_ALERT_COLS = "alert_id, window_start, entity_type, entity_key, network, risk_score, band, case_id"


def _rows(result: Any) -> list[Row]:
    return [dict(r) for r in result.mappings().all()]


def _alert(row: Row) -> Row:
    row["risk_score"] = float(row["risk_score"])
    return row


class SqlRepo:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self._current: ContextVar[Connection | None] = ContextVar(f"sqlrepo_conn_{id(self)}", default=None)

    def current_connection(self) -> Connection | None:
        """Connection for a participating store; None when outside a repo transaction."""
        return self._current.get()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        if self._current.get() is not None:  # nested call joins the outer transaction
            yield
            return
        with self.engine.begin() as conn:  # commits on success, rolls back if an exception escapes
            token = self._current.set(conn)
            try:
                yield
            finally:
                self._current.reset(token)

    @contextmanager
    def _c(self) -> Iterator[Connection]:
        conn = self._current.get()
        if conn is not None:
            yield conn
        else:
            with self.engine.begin() as own:
                yield own

    def upsert_user_ref(self, sub: str, username: str, now: datetime) -> None:
        with self._c() as c:
            c.execute(text("""INSERT INTO user_refs (sub, username, last_seen) VALUES (:sub, :u, :now)
                              ON CONFLICT (sub) DO UPDATE SET username = EXCLUDED.username,
                                                              last_seen = EXCLUDED.last_seen"""),
                      {"sub": sub, "u": username, "now": now})

    # alerts
    def save_detection(self, rules: Sequence[RuleMetadata], alerts: pd.DataFrame,
                       components: pd.DataFrame) -> None:
        from fraud_engine.pg_store import PostgresStore
        PostgresStore(self.engine, self.current_connection).save_detection(rules, alerts, components)

    def list_alerts(self, *, band: str | None, network: str | None, entity_type: str | None,
                    limit: int, offset: int) -> tuple[list[Row], int]:
        p = {"band": band, "network": network, "entity_type": entity_type, "limit": limit, "offset": offset}
        where = ("WHERE (CAST(:band AS text) IS NULL OR band = CAST(:band AS text))"
                 " AND (CAST(:network AS text) IS NULL OR network = CAST(:network AS text))"
                 " AND (CAST(:entity_type AS text) IS NULL OR entity_type = CAST(:entity_type AS text))")
        with self._c() as c:
            rows = _rows(c.execute(text(f"SELECT {_ALERT_COLS} FROM fraud_alerts {where} "  # noqa: S608 (constants only)
                                        "ORDER BY risk_score DESC, alert_id ASC LIMIT :limit OFFSET :offset"), p))
            total = c.execute(text(f"SELECT COUNT(*) FROM fraud_alerts {where}"), p).scalar_one()  # noqa: S608
        return [_alert(r) for r in rows], int(total)

    def get_alert(self, alert_id: int) -> Row | None:
        with self._c() as c:
            rows = _rows(c.execute(text(f"SELECT {_ALERT_COLS} FROM fraud_alerts WHERE alert_id = :id"),  # noqa: S608
                                   {"id": alert_id}))
            if not rows:
                return None
            comps = _rows(c.execute(text("""SELECT r.rule_key, r.version AS rule_version, r.weight,
                                                   k.severity, k.evidence
                                            FROM risk_score_components k JOIN fraud_rules r USING (rule_pk)
                                            WHERE k.alert_id = :id ORDER BY r.rule_key"""), {"id": alert_id}))
        alert = _alert(rows[0])
        alert["components"] = [{"rule_key": k["rule_key"], "rule_version": k["rule_version"],
                                "severity": float(k["severity"]),
                                "contribution": float(k["weight"]) * float(k["severity"]),
                                "evidence": k["evidence"]} for k in comps]
        return alert

    def alert_summary(self) -> Row:
        with self._c() as c:
            counts = {r["band"]: int(r["n"]) for r in _rows(c.execute(
                text("SELECT band, COUNT(*) AS n FROM fraud_alerts GROUP BY band")))}
            last = c.execute(text("SELECT MAX(window_start) FROM fraud_alerts")).scalar_one()
        by_band = {b: counts.get(b, 0) for b in BANDS}
        return {"alerts_total": sum(by_band.values()), "alerts_by_band": by_band, "last_window_start": last}

    # rules
    def list_rules(self) -> list[Row]:
        with self._c() as c:
            rows = _rows(c.execute(text("""SELECT DISTINCT ON (rule_key) rule_key, version, rule_type, params,
                                                  weight, enabled FROM fraud_rules
                                           WHERE rule_type <> 'anomaly_model'
                                           ORDER BY rule_key, version DESC""")))
        return [{**r, "weight": float(r["weight"])} for r in rows]

    def get_latest_rule(self, rule_key: str) -> Row | None:
        with self._c() as c:
            rows = _rows(c.execute(text("""SELECT rule_key, version, rule_type, params, weight, enabled
                                           FROM fraud_rules WHERE rule_key = :k
                                             AND rule_type <> 'anomaly_model'
                                           ORDER BY version DESC LIMIT 1"""), {"k": rule_key}))
        return {**rows[0], "weight": float(rows[0]["weight"])} if rows else None

    def get_rule_metadata(self, rule_key: str, version: int) -> Row | None:
        with self._c() as c:
            rows = _rows(c.execute(text("""SELECT rule_key, version, rule_type, params, weight, enabled
                                           FROM fraud_rules WHERE rule_key = :k AND version = :v"""),
                                   {"k": rule_key, "v": version}))
        return {**rows[0], "weight": float(rows[0]["weight"])} if rows else None

    def add_rule_version(self, rule_key: str, rule_type: str, params: dict[str, Any], weight: float,
                         enabled: bool) -> Row:
        with self._c() as c:
            # Serialize version allocation per key; the unique constraint remains the final safeguard.
            c.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": rule_key})
            version = c.execute(text("SELECT COALESCE(MAX(version), 0) + 1 FROM fraud_rules WHERE rule_key = :k"),
                                {"k": rule_key}).scalar_one()
            c.execute(text("""INSERT INTO fraud_rules (rule_key, version, rule_type, params, weight, enabled)
                              VALUES (:k, :v, :t, CAST(:p AS jsonb), :w, :e)"""),
                      {"k": rule_key, "v": version, "t": rule_type, "p": json.dumps(params), "w": weight,
                       "e": enabled})
        return {"rule_key": rule_key, "version": int(version), "rule_type": rule_type, "params": dict(params),
                "weight": float(weight), "enabled": enabled}

    def seed_default_rules(self, rules: Sequence[RuleMetadata]) -> int:
        """Atomically seed missing default rules so concurrent process starts cannot duplicate versions."""
        with self.transaction():
            conn = self.current_connection()
            assert conn is not None
            conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _RULE_SEED_LOCK_KEY})
            existing = {row["rule_key"] for row in self.list_rules()}
            added = 0
            for rule in rules:
                if rule.rule_key in existing:
                    continue
                self.add_rule_version(rule.rule_key, rule.rule_type, dict(rule.params),
                                      rule.weight, rule.enabled)
                existing.add(rule.rule_key)
                added += 1
            return added

    # cases
    def create_case(self, *, priority: str, opened_by: str, alert_ids: list[int], now: datetime) -> Row:
        with self._c() as c:
            # Lock targets in stable order so concurrent case creation cannot link an alert twice.
            locked = c.execute(text("SELECT alert_id FROM fraud_alerts WHERE alert_id = ANY(:ids) "
                                    "ORDER BY alert_id FOR UPDATE"), {"ids": alert_ids}).scalars().all()
            if len(locked) != len(alert_ids):
                raise NotFoundError("one or more alerts")
            cid = c.execute(text("""INSERT INTO fraud_cases (status, priority, opened_by_sub, opened_at)
                                    VALUES ('New', :p, :by, :now) RETURNING case_id"""),
                            {"p": priority, "by": opened_by, "now": now}).scalar_one()
            linked = c.execute(text("UPDATE fraud_alerts SET case_id = :cid "
                                    "WHERE alert_id = ANY(:ids) AND case_id IS NULL"),
                               {"cid": cid, "ids": alert_ids}).rowcount
            if linked != len(alert_ids):
                raise ConflictError("an alert already belongs to a case")  # caller's transaction rolls back
        return {"case_id": int(cid), "status": "New", "priority": priority, "assignee_sub": None,
                "outcome_label": None, "opened_by_sub": opened_by, "opened_at": now, "closed_at": None}

    def get_case(self, case_id: int, for_update: bool = False) -> Row | None:
        sql = ("SELECT case_id, status, priority, assignee_sub, outcome_label, opened_by_sub, opened_at, "
               "closed_at FROM fraud_cases WHERE case_id = :id")
        with self._c() as c:
            rows = _rows(c.execute(text(sql + (" FOR UPDATE" if for_update else "")), {"id": case_id}))
            if not rows:
                return None
            case = rows[0]
            case["alert_ids"] = [r["alert_id"] for r in _rows(c.execute(
                text("SELECT alert_id FROM fraud_alerts WHERE case_id = :id ORDER BY alert_id"), {"id": case_id}))]
            case["events"] = _rows(c.execute(text(
                "SELECT id, case_id, from_status, to_status, actor_sub, at, reason FROM case_events "
                "WHERE case_id = :id ORDER BY id"), {"id": case_id}))
            case["notes"] = _rows(c.execute(text(
                "SELECT id, case_id, author_sub, body, at FROM case_notes WHERE case_id = :id ORDER BY id"),
                {"id": case_id}))
        return case

    def list_cases(self, *, status: str | None, limit: int, offset: int) -> tuple[list[Row], int]:
        p = {"status": status, "limit": limit, "offset": offset}
        where = "WHERE (CAST(:status AS text) IS NULL OR status = CAST(:status AS text))"
        with self._c() as c:
            rows = _rows(c.execute(text(
                "SELECT case_id, status, priority, assignee_sub, outcome_label, opened_by_sub, opened_at, "
                f"closed_at FROM fraud_cases {where} ORDER BY case_id DESC LIMIT :limit OFFSET :offset"), p))  # noqa: S608
            total = c.execute(text(f"SELECT COUNT(*) FROM fraud_cases {where}"), p).scalar_one()  # noqa: S608
        return rows, int(total)

    def set_case_state(self, case_id: int, status: str, assignee_sub: str | None,
                       outcome_label: str | None, closed_at: datetime | None) -> None:
        with self._c() as c:
            c.execute(text("UPDATE fraud_cases SET status = :s, assignee_sub = :a, outcome_label = :o, "
                           "closed_at = :c WHERE case_id = :id"),
                      {"s": status, "a": assignee_sub, "o": outcome_label, "c": closed_at, "id": case_id})

    def add_case_event(self, case_id: int, from_status: str | None, to_status: str, actor_sub: str,
                       at: datetime, reason: str | None) -> None:
        with self._c() as c:
            c.execute(text("INSERT INTO case_events (case_id, from_status, to_status, actor_sub, at, reason) "
                           "VALUES (:id, :f, :t, :a, :at, :r)"),
                      {"id": case_id, "f": from_status, "t": to_status, "a": actor_sub, "at": at, "r": reason})

    def add_case_note(self, case_id: int, author_sub: str, body: str, at: datetime) -> Row:
        with self._c() as c:
            nid = c.execute(text("INSERT INTO case_notes (case_id, author_sub, body, at) "
                                 "VALUES (:id, :a, :b, :at) RETURNING id"),
                            {"id": case_id, "a": author_sub, "b": body, "at": at}).scalar_one()
        return {"id": int(nid), "case_id": case_id, "author_sub": author_sub, "body": body, "at": at}

    def case_status_counts(self) -> dict[str, int]:
        with self._c() as c:
            return {r["status"]: int(r["n"]) for r in _rows(c.execute(
                text("SELECT status, COUNT(*) AS n FROM fraud_cases GROUP BY status")))}

    # audit
    def append_audit(self, fields: Row) -> Row:
        with self._c() as c:
            c.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _AUDIT_LOCK_KEY})
            prev = c.execute(text("SELECT row_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1")).scalar()
            prev = prev or audit.GENESIS
            row_hash = audit.entry_hash(prev, fields)
            audit_id = c.execute(text("""INSERT INTO audit_log (at, actor_sub, action, resource_type, resource_id,
                                         outcome, source_ip, details, prev_hash, row_hash)
                                         VALUES (:at, :actor_sub, :action, :resource_type, :resource_id, :outcome,
                                                 :source_ip, CAST(:details AS jsonb), :prev, :hash)
                                         RETURNING audit_id"""),
                                 {**{k: fields.get(k) for k in ("at", "actor_sub", "action", "resource_type",
                                                                "resource_id", "outcome", "source_ip")},
                                  "details": json.dumps(fields.get("details") or {}, sort_keys=True),
                                  "prev": prev, "hash": row_hash}).scalar_one()
        return {"audit_id": int(audit_id), **fields, "prev_hash": prev, "row_hash": row_hash}

    _AUDIT_COLS = ("audit_id, at, actor_sub, action, resource_type, resource_id, outcome, source_ip, "
                   "details, prev_hash, row_hash")

    def list_audit(self, *, limit: int, offset: int) -> tuple[list[Row], int]:
        with self._c() as c:
            rows = _rows(c.execute(text(f"SELECT {self._AUDIT_COLS} FROM audit_log "  # noqa: S608
                                        "ORDER BY audit_id DESC LIMIT :l OFFSET :o"), {"l": limit, "o": offset}))
            total = c.execute(text("SELECT COUNT(*) FROM audit_log")).scalar_one()
        return rows, int(total)

    def iter_audit(self) -> list[Row]:
        """Loads the whole chain in memory; fine at current volumes, batch it before audit grows large."""
        with self._c() as c:
            return _rows(c.execute(text(f"SELECT {self._AUDIT_COLS} FROM audit_log ORDER BY audit_id")))  # noqa: S608

    def audit_count(self) -> int:
        with self._c() as c:
            return int(c.execute(text("SELECT COUNT(*) FROM audit_log")).scalar_one())
