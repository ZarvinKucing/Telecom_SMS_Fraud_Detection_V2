"""Request dispatcher. Fixed order, so a request can never skip a step:

  route match -> authenticate (401) -> user ref -> permission (403, audited) -> validate (422)
  -> extra permission (403, audited) -> handler inside ONE repo transaction -> response

State-changing routes must write an audit row; a handler that forgets is rolled back with a 500.
Unexpected exceptions return a generic 500 and are logged, never echoed to the client.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

import pandas as pd

from backend.auth.permissions import Principal
from backend.auth.tokens import AuthError
from backend.errors import ApiError
from backend.repo import Repo
from backend.services import audit
from backend.validation import ValidationError
from fraud_engine.ingest import RecordStore

log = logging.getLogger(__name__)
PUBLIC = "public"  # explicit marker: a route with permission=None is a bug, not a public route


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class Request:
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)
    body: Any = None
    client_ip: str | None = None


@dataclass
class Response:
    status: int
    body: Any
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class AppContext:
    repo: Repo
    store: RecordStore
    verify: Callable[[str], Principal]
    clock: Callable[[], datetime] = utcnow
    source_tz: str = "UTC"
    max_ingest_bytes: int = 5_000_000
    on_security_event: Callable[[dict[str, Any]], None] = lambda event: None  # Phase 4 hook


Handler = Callable[[AppContext, Principal | None, Request, dict[str, Any]], tuple[int, Any]]
Validator = Callable[[dict[str, str], dict[str, str], Any], dict[str, Any]]


@dataclass(frozen=True)
class Route:
    method: str
    pattern: str
    permission: str | None
    handler: Handler
    validator: Validator | None = None
    writes: bool = False
    extra_permission: Callable[[dict[str, Any]], str | None] | None = None
    summary: str = ""

    @property
    def regex(self) -> re.Pattern[str]:
        return re.compile(re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", self.pattern))


class Router:
    def __init__(self) -> None:
        self.routes: list[Route] = []

    def add(self, method: str, pattern: str, permission: str | None, *, validator: Validator | None = None,
            writes: bool = False, extra_permission: Callable[[dict[str, Any]], str | None] | None = None,
            summary: str = "") -> Callable[[Handler], Handler]:
        def deco(fn: Handler) -> Handler:
            self.routes.append(Route(method, pattern, permission, fn, validator, writes, extra_permission,
                                     summary or (fn.__doc__ or "").strip()))
            return fn
        return deco


def to_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): to_json(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [to_json(v) for v in value]
    if isinstance(value, pd.Timestamp | datetime | date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if hasattr(value, "item"):  # numpy scalar
        return to_json(value.item())
    return value


class Dispatcher:
    def __init__(self, ctx: AppContext, router: Router) -> None:
        self.ctx, self.router = ctx, router

    def _match(self, req: Request) -> tuple[Route, dict[str, str]] | Response:
        path_hit = False
        for route in self.router.routes:
            m = route.regex.fullmatch(req.path)
            if m:
                path_hit = True
                if route.method == req.method:
                    return route, m.groupdict()
        return Response(405, {"error": "method_not_allowed"}) if path_hit else Response(404, {"error": "not_found"})

    def _event(self, kind: str, req: Request, **detail: Any) -> None:
        try:
            self.ctx.on_security_event({"kind": kind, "path": req.path, "method": req.method,
                                        "ip": req.client_ip, **detail})
        except Exception:
            log.exception("security event sink failed")

    def _deny(self, principal: Principal, route: Route, req: Request, required: str) -> Response:
        self._event("authz.denied", req, actor=principal.sub, required=required)
        try:
            audit.record(self.ctx.repo, self.ctx.clock, principal.sub, "authz.denied", "route",
                         f"{route.method} {route.pattern}", outcome="denied", source_ip=req.client_ip,
                         details={"required": required})
        except Exception:
            log.exception("failed to audit permission denial")
        return Response(403, {"error": "forbidden"})

    def handle(self, req: Request) -> Response:
        matched = self._match(req)
        if isinstance(matched, Response):
            return matched
        route, params = matched
        principal: Principal | None = None
        if route.permission != PUBLIC:
            header = req.headers.get("authorization", "")
            scheme, _, token = header.partition(" ")
            if scheme.lower() != "bearer" or not token.strip():
                self._event("authn.missing", req)
                return Response(401, {"error": "unauthorized"}, {"WWW-Authenticate": "Bearer"})
            try:
                principal = self.ctx.verify(token.strip())
            except AuthError as exc:
                log.warning("token rejected", extra={"reason": exc.code, "path": req.path})
                self._event("authn.failed", req, reason=exc.code)
                return Response(401, {"error": "unauthorized"}, {"WWW-Authenticate": "Bearer"})
            try:
                self.ctx.repo.upsert_user_ref(principal.sub, principal.username, self.ctx.clock())
            except Exception:
                log.exception("user ref upsert failed")
                return Response(500, {"error": "internal_error"})
            if route.permission is None or route.permission not in principal.permissions:
                return self._deny(principal, route, req, str(route.permission))
        try:
            data = route.validator(params, req.query, req.body) if route.validator else {}
        except ValidationError as exc:
            return Response(422, {"error": "validation_error", "details": exc.errors})
        extra = route.extra_permission(data) if route.extra_permission else None
        if extra and principal is not None and extra not in principal.permissions:
            return self._deny(principal, route, req, extra)
        try:
            with self.ctx.repo.transaction():
                before = self.ctx.repo.audit_count()
                status, body = route.handler(self.ctx, principal, req, data)
                if route.writes and self.ctx.repo.audit_count() <= before:
                    raise RuntimeError(f"state-changing route {route.method} {route.pattern} wrote no audit row")
            return Response(status, to_json(body))
        except ApiError as exc:
            return Response(exc.status, {"error": exc.code, "message": exc.message})
        except Exception:
            log.exception("unhandled error", extra={"path": req.path, "method": req.method})
            return Response(500, {"error": "internal_error"})
