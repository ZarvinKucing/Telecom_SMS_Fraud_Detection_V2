"""Shared fixtures: a dispatcher over MemoryRepo, real RS256 tokens, alerts from synthetic data."""
from __future__ import annotations

import functools
import itertools
from datetime import UTC, datetime, timedelta
from typing import Any

from backend.auth.testing import AUDIENCE, ISSUER, TestKeyPair, make_token
from backend.auth.tokens import verify_token
from backend.core import AppContext, Dispatcher, Request, Response
from backend.handlers import router
from backend.memory_repo import MemoryRepo
from fraud_engine.anomaly import AnomalyConfig, as_rule_record
from fraud_engine.memory_store import InMemoryStore
from fraud_engine.normalize import normalize_frame
from fraud_engine.pipeline import run_detection
from fraud_engine.rule_registry import load_rules, seed_default_rules
from synthetic_data.generate_cdr import GeneratorConfig, generate_cdr

KEYS = TestKeyPair.generate()
ROLES = ("administrator", "fraud_analyst", "security_analyst", "viewer")


@functools.cache
def _detection():
    gen = generate_cdr(GeneratorConfig(seed=1))
    good = normalize_frame(gen.records).good
    return gen, good, run_detection(good, anomaly=AnomalyConfig())


def make_clock():
    base, counter = datetime(2026, 1, 12, tzinfo=UTC), itertools.count()
    return lambda: base + timedelta(seconds=next(counter))


class Api:
    def __init__(self, seed_alerts: bool = True) -> None:
        self.repo = MemoryRepo()
        self.store = InMemoryStore()
        self.events: list[dict[str, Any]] = []
        self.ctx = AppContext(
            repo=self.repo, store=self.store, clock=make_clock(),
            verify=lambda t: verify_token(t, lambda _t: KEYS.public_pem, ISSUER, AUDIENCE),
            on_security_event=self.events.append, max_ingest_bytes=200_000)
        self.dispatcher = Dispatcher(self.ctx, router)
        seed_default_rules(self.repo)
        if seed_alerts:
            res = _detection()[2]
            metadata = [*load_rules(self.repo), as_rule_record(AnomalyConfig())]
            self.repo.save_detection(metadata, res.alerts, res.components)

    def token(self, *roles: str, sub: str = "user-1") -> str:
        return make_token(KEYS.private_pem, sub, list(roles))

    def call(self, method: str, path: str, *roles: str, query: dict[str, str] | None = None,
             body: Any = None, token: str | None = None, sub: str = "user-1", ip: str = "10.0.0.9") -> Response:
        headers = {}
        if token is not None or roles:
            headers["authorization"] = "Bearer " + (token or self.token(*roles, sub=sub))
        return self.dispatcher.handle(Request(method, path, headers, query or {}, body, ip))

    def alert_ids(self) -> list[int]:
        rows, _ = self.repo.list_alerts(band=None, network=None, entity_type=None, limit=200, offset=0)
        return [r["alert_id"] for r in rows]

    def new_case(self, actor: str = "analyst-0", n: int = 1, skip: int = 0) -> int:
        from backend.services import cases
        ids = self.alert_ids()[skip:skip + n]
        with self.repo.transaction():
            return cases.create_case(self.repo, self.ctx.clock, actor, None, ids, None)["case_id"]

    def snapshot(self) -> tuple[int, int, int, int]:
        return (len(self.repo.alerts), len(self.repo.cases), len(self.repo.rules), len(self.repo.audit))
