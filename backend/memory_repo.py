"""In-memory Repo with real transaction semantics (snapshot + rollback)."""
from __future__ import annotations

import copy
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime
from typing import Any

import pandas as pd

from backend.errors import ConflictError, NotFoundError
from backend.services import audit
from fraud_engine.rules import RuleMetadata, detection_rule_metadata, rule_metadata_values

Row = dict[str, Any]
BANDS = ("low", "medium", "high", "critical")
_STATE = ("user_refs", "alerts", "_alert_ids", "components", "rules", "cases", "events", "notes", "audit",
          "rule_metadata", "_seq")


class MemoryRepo:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.user_refs: dict[str, Row] = {}
        self.alerts: dict[int, Row] = {}
        self._alert_ids: dict[tuple[Any, ...], int] = {}
        self.components: dict[int, list[Row]] = {}
        self.rules: list[Row] = []
        self.rule_metadata: dict[tuple[str, int], Row] = {}
        self.cases: dict[int, Row] = {}
        self.events: list[Row] = []
        self.notes: list[Row] = []
        self.audit: list[Row] = []
        self._seq: dict[str, int] = {}

    def _next(self, name: str) -> int:
        self._seq[name] = self._seq.get(name, 0) + 1
        return self._seq[name]

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            snapshot = {k: copy.deepcopy(getattr(self, k)) for k in _STATE}
            try:
                yield
            except BaseException:
                for k, v in snapshot.items():
                    setattr(self, k, v)
                raise

    def upsert_user_ref(self, sub: str, username: str, now: datetime) -> None:
        with self._lock:
            self.user_refs[sub] = {"sub": sub, "username": username, "last_seen": now}

    # alerts
    def save_detection(self, rules: Sequence[RuleMetadata], alerts: pd.DataFrame,
                       components: pd.DataFrame) -> None:
        metadata = detection_rule_metadata(rules, components)
        keys = ["window_start", "entity_type", "entity_key", "network"]
        with self._lock:
            for key, rule in metadata.items():
                row = self.rule_metadata.setdefault(key, rule_metadata_values(rule))
                if row["rule_type"] != "anomaly_model" and not any(
                    (r["rule_key"], int(r["version"])) == key for r in self.rules
                ):
                    self.rules.append(copy.deepcopy(row))
            by_key: dict[tuple[Any, ...], list[Row]] = {}
            for c in components.to_dict("records"):
                k = (pd.Timestamp(c["window_start"]).to_pydatetime(), c["entity_type"], c["entity_key"], c["network"])
                by_key.setdefault(k, []).append({
                    "rule_key": c["rule_key"], "rule_version": int(c["rule_version"]),
                    "severity": float(c["severity"]), "contribution": float(c["contribution"]),
                    "evidence": dict(c["evidence"])})
            for a in alerts.to_dict("records"):
                k = (pd.Timestamp(a["window_start"]).to_pydatetime(), a["entity_type"], a["entity_key"], a["network"])
                aid = self._alert_ids.get(k)
                if aid is None:
                    aid = self._next("alert")
                    self._alert_ids[k] = aid
                    self.alerts[aid] = {"alert_id": aid, **dict(zip(keys, k, strict=True)), "case_id": None}
                self.alerts[aid].update(risk_score=float(a["risk_score"]), band=a["band"])
                self.components[aid] = by_key.get(k, [])

    def list_alerts(self, *, band: str | None, network: str | None, entity_type: str | None,
                    limit: int, offset: int) -> tuple[list[Row], int]:
        with self._lock:
            rows = [a for a in self.alerts.values()
                    if (band is None or a["band"] == band) and (network is None or a["network"] == network)
                    and (entity_type is None or a["entity_type"] == entity_type)]
            rows.sort(key=lambda a: (-a["risk_score"], a["alert_id"]))
            return [dict(r) for r in rows[offset:offset + limit]], len(rows)

    def get_alert(self, alert_id: int) -> Row | None:
        with self._lock:
            a = self.alerts.get(alert_id)
            return None if a is None else {**a, "components": copy.deepcopy(self.components.get(alert_id, []))}

    def alert_summary(self) -> Row:
        with self._lock:
            by_band = dict.fromkeys(BANDS, 0)
            for a in self.alerts.values():
                by_band[a["band"]] += 1
            last = max((a["window_start"] for a in self.alerts.values()), default=None)
            return {"alerts_total": len(self.alerts), "alerts_by_band": by_band, "last_window_start": last}

    # rules
    def list_rules(self) -> list[Row]:
        with self._lock:
            latest: dict[str, Row] = {}
            for r in self.rules:
                if r["rule_key"] not in latest or r["version"] > latest[r["rule_key"]]["version"]:
                    latest[r["rule_key"]] = r
            return [copy.deepcopy(latest[k]) for k in sorted(latest)]

    def get_latest_rule(self, rule_key: str) -> Row | None:
        return next((r for r in self.list_rules() if r["rule_key"] == rule_key), None)

    def get_rule_metadata(self, rule_key: str, version: int) -> Row | None:
        key = (rule_key, int(version))
        with self._lock:
            row = self.rule_metadata.get(key)
            if row is None:
                row = next((r for r in self.rules if (r["rule_key"], int(r["version"])) == key), None)
            return copy.deepcopy(row) if row is not None else None

    def add_rule_version(self, rule_key: str, rule_type: str, params: dict[str, Any], weight: float,
                         enabled: bool) -> Row:
        with self._lock:
            version = 1 + max((r["version"] for r in self.rules if r["rule_key"] == rule_key), default=0)
            row = {"rule_key": rule_key, "version": version, "rule_type": rule_type,
                   "params": dict(params), "weight": float(weight), "enabled": enabled}
            self.rules.append(row)
            self.rule_metadata.setdefault((rule_key, version), copy.deepcopy(row))
            return copy.deepcopy(row)

    # cases
    def create_case(self, *, priority: str, opened_by: str, alert_ids: list[int], now: datetime) -> Row:
        with self._lock:
            for aid in alert_ids:
                if aid not in self.alerts:
                    raise NotFoundError(f"alert {aid}")
                if self.alerts[aid]["case_id"] is not None:
                    raise ConflictError(f"alert {aid} already belongs to a case")
            cid = self._next("case")
            self.cases[cid] = {"case_id": cid, "status": "New", "priority": priority, "assignee_sub": None,
                               "outcome_label": None, "opened_by_sub": opened_by, "opened_at": now,
                               "closed_at": None}
            for aid in alert_ids:
                self.alerts[aid]["case_id"] = cid
            return dict(self.cases[cid])

    def get_case(self, case_id: int, for_update: bool = False) -> Row | None:
        with self._lock:
            c = self.cases.get(case_id)
            if c is None:
                return None
            return {**c,
                    "alert_ids": sorted(a["alert_id"] for a in self.alerts.values() if a["case_id"] == case_id),
                    "events": [dict(e) for e in self.events if e["case_id"] == case_id],
                    "notes": [dict(n) for n in self.notes if n["case_id"] == case_id]}

    def list_cases(self, *, status: str | None, limit: int, offset: int) -> tuple[list[Row], int]:
        with self._lock:
            rows = sorted((c for c in self.cases.values() if status is None or c["status"] == status),
                          key=lambda c: -c["case_id"])
            return [dict(r) for r in rows[offset:offset + limit]], len(rows)

    def set_case_state(self, case_id: int, status: str, assignee_sub: str | None,
                       outcome_label: str | None, closed_at: datetime | None) -> None:
        with self._lock:
            self.cases[case_id].update(status=status, assignee_sub=assignee_sub,
                                       outcome_label=outcome_label, closed_at=closed_at)

    def add_case_event(self, case_id: int, from_status: str | None, to_status: str, actor_sub: str,
                       at: datetime, reason: str | None) -> None:
        with self._lock:
            self.events.append({"id": self._next("event"), "case_id": case_id, "from_status": from_status,
                                "to_status": to_status, "actor_sub": actor_sub, "at": at, "reason": reason})

    def add_case_note(self, case_id: int, author_sub: str, body: str, at: datetime) -> Row:
        with self._lock:
            note = {"id": self._next("note"), "case_id": case_id, "author_sub": author_sub, "body": body, "at": at}
            self.notes.append(note)
            return dict(note)

    def case_status_counts(self) -> dict[str, int]:
        with self._lock:
            out: dict[str, int] = {}
            for c in self.cases.values():
                out[c["status"]] = out.get(c["status"], 0) + 1
            return out

    # audit
    def append_audit(self, fields: Row) -> Row:
        with self._lock:
            prev = self.audit[-1]["row_hash"] if self.audit else audit.GENESIS
            row = {"audit_id": self._next("audit"), **fields, "prev_hash": prev,
                   "row_hash": audit.entry_hash(prev, fields)}
            self.audit.append(row)
            return copy.deepcopy(row)

    def list_audit(self, *, limit: int, offset: int) -> tuple[list[Row], int]:
        with self._lock:
            rows = list(reversed(self.audit))
            return copy.deepcopy(rows[offset:offset + limit]), len(rows)

    def iter_audit(self) -> list[Row]:
        with self._lock:
            return copy.deepcopy(self.audit)

    def audit_count(self) -> int:
        with self._lock:
            return len(self.audit)
