"""Hash-chained audit trail. Detects edits and mid-chain deletions.

Each row stores the hash of the previous row and of its own content. Known limits: removing the most
recent rows (tail truncation) leaves a valid shorter chain, and a privileged database owner can
rewrite the whole chain. Details must contain only JSON-stable values (str/int/bool/None/list/dict).
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

GENESIS = "0" * 64
_FIELDS = ("at", "actor_sub", "action", "resource_type", "resource_id", "outcome", "source_ip", "details")


def _iso(at: datetime | str) -> str:
    if isinstance(at, str):
        at = datetime.fromisoformat(at)
    return at.astimezone(UTC).isoformat(timespec="microseconds")


def entry_hash(prev_hash: str, fields: dict[str, Any]) -> str:
    payload = {k: fields.get(k) for k in _FIELDS}
    payload["at"] = _iso(payload["at"])
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{prev_hash}|{body}".encode()).hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    rows: int
    first_bad_audit_id: int | None = None
    reason: str | None = None


def verify_chain(rows: Iterable[dict[str, Any]]) -> VerifyResult:
    prev, n = GENESIS, 0
    for row in rows:
        n += 1
        if row["prev_hash"] != prev:
            return VerifyResult(False, n, row["audit_id"], "broken_link")
        if entry_hash(prev, row) != row["row_hash"]:
            return VerifyResult(False, n, row["audit_id"], "hash_mismatch")
        prev = row["row_hash"]
    return VerifyResult(True, n)


def record(repo: Any, clock: Callable[[], datetime], actor_sub: str | None, action: str,
           resource_type: str, resource_id: str, outcome: str = "success", source_ip: str | None = None,
           details: dict[str, Any] | None = None) -> dict[str, Any]:
    return repo.append_audit({"at": clock(), "actor_sub": actor_sub, "action": action,
                              "resource_type": resource_type, "resource_id": str(resource_id),
                              "outcome": outcome, "source_ip": source_ip, "details": details or {}})
