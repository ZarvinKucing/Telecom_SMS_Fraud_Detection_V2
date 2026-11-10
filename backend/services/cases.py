"""Case workflow. Every function runs inside the dispatcher's transaction, so the case change, the
case event and the audit row commit together or not at all."""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from backend.errors import ConflictError, NotFoundError
from backend.services import audit

STATUSES = ("New", "Triaged", "Investigating", "NeedsInfo", "ConfirmedFraud", "FalsePositive", "Closed")
TRANSITIONS: dict[str, tuple[str, ...]] = {
    "New": ("Triaged",),
    "Triaged": ("Investigating",),
    "Investigating": ("NeedsInfo", "ConfirmedFraud", "FalsePositive"),
    "NeedsInfo": ("Investigating",),
    "ConfirmedFraud": ("Closed",),
    "FalsePositive": ("Closed",),
    "Closed": (),  # reopening is a separate, explicit, audited action
}
PRIORITIES = ("P1", "P2", "P3", "P4")
_BAND_PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}


def _get(repo: Any, case_id: int, lock: bool = False) -> dict[str, Any]:
    case = repo.get_case(case_id, for_update=lock)
    if case is None:
        raise NotFoundError(f"case {case_id}")
    return case


def create_case(repo: Any, clock: Callable[[], datetime], actor: str, ip: str | None,
                alert_ids: list[int], priority: str | None) -> dict[str, Any]:
    alerts = []
    for aid in alert_ids:
        alert = repo.get_alert(aid)
        if alert is None:
            raise NotFoundError(f"alert {aid}")
        if alert["case_id"] is not None:
            raise ConflictError(f"alert {aid} already belongs to case {alert['case_id']}")
        alerts.append(alert)
    if priority is None:
        priority = min((_BAND_PRIORITY[a["band"]] for a in alerts), key=PRIORITIES.index)
    now = clock()
    case = repo.create_case(priority=priority, opened_by=actor, alert_ids=alert_ids, now=now)
    repo.add_case_event(case["case_id"], None, "New", actor, now, None)
    audit.record(repo, clock, actor, "case.create", "case", case["case_id"], source_ip=ip,
                 details={"alert_ids": alert_ids, "priority": priority})
    return _get(repo, case["case_id"])


def transition_case(repo: Any, clock: Callable[[], datetime], actor: str, ip: str | None,
                    case_id: int, to_status: str, reason: str | None) -> dict[str, Any]:
    case = _get(repo, case_id, lock=True)
    current = case["status"]
    if to_status not in TRANSITIONS[current]:
        allowed = list(TRANSITIONS[current])
        raise ConflictError(f"cannot move {current} -> {to_status}; allowed: {allowed}")
    now = clock()
    assignee = case["assignee_sub"]
    if to_status == "Investigating" and assignee is None:
        assignee = actor
    outcome, closed_at = case["outcome_label"], None
    if to_status == "Closed":
        outcome = "confirmed_fraud" if current == "ConfirmedFraud" else "false_positive"
        closed_at = now
    repo.set_case_state(case_id, to_status, assignee, outcome, closed_at)
    repo.add_case_event(case_id, current, to_status, actor, now, reason)
    audit.record(repo, clock, actor, "case.transition", "case", case_id, source_ip=ip,
                 details={"from": current, "to": to_status, "has_reason": bool(reason)})
    return _get(repo, case_id)


def reopen_case(repo: Any, clock: Callable[[], datetime], actor: str, ip: str | None,
                case_id: int, reason: str) -> dict[str, Any]:
    case = _get(repo, case_id, lock=True)
    if case["status"] != "Closed":
        raise ConflictError("only a closed case can be reopened")
    now = clock()
    repo.set_case_state(case_id, "Investigating", actor, None, None)
    repo.add_case_event(case_id, "Closed", "Investigating", actor, now, reason)
    audit.record(repo, clock, actor, "case.reopen", "case", case_id, source_ip=ip,
                 details={"previous_outcome": case["outcome_label"]})
    return _get(repo, case_id)


def add_note(repo: Any, clock: Callable[[], datetime], actor: str, ip: str | None,
             case_id: int, body: str) -> dict[str, Any]:
    _get(repo, case_id, lock=True)
    note = repo.add_case_note(case_id, actor, body, clock())
    audit.record(repo, clock, actor, "case.note", "case", case_id, source_ip=ip,
                 details={"note_id": note["id"], "length": len(body)})
    return note
