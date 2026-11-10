"""FastAPI transport adapter. All behaviour lives in backend.core.Dispatcher; this only moves bytes.

Routes are registered from the same table the authorization tests exercise. Request validation is
the strict hand-written layer in backend/validation.py; per-route validators can be replaced without
changing the transport adapter.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import Any

from backend.core import AppContext, Dispatcher, Request
from backend.handlers import router
from backend.openapi import build_spec

MAX_BODY_FACTOR = 2  # JSON-escaped CSV can exceed the raw byte limit; the handler enforces the exact one


def create_app(ctx: AppContext, *, on_shutdown: Callable[[], Any] | None = None,
               openapi_public: bool = False) -> Any:
    from fastapi import FastAPI
    from starlette.concurrency import run_in_threadpool
    from starlette.requests import Request as StarletteRequest
    from starlette.responses import JSONResponse

    @asynccontextmanager
    async def lifespan(_app: Any):
        try:
            yield
        finally:
            if on_shutdown is not None:
                on_shutdown()

    app = FastAPI(title="Fraud & Security Platform API", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    dispatcher = Dispatcher(ctx, router)
    spec = build_spec(router, openapi_public=openapi_public)
    body_limit = ctx.max_ingest_bytes * MAX_BODY_FACTOR + 4096

    async def endpoint(request: StarletteRequest) -> JSONResponse:
        chunks: list[bytes] = []
        body_size = 0
        async for chunk in request.stream():
            body_size += len(chunk)
            if body_size > body_limit:
                return JSONResponse({"error": "payload_too_large"}, status_code=413)
            chunks.append(chunk)
        raw = b"".join(chunks)
        body: Any = None
        if raw:
            try:
                body = json.loads(raw)
            except ValueError:
                return JSONResponse({"error": "invalid_json"}, status_code=400)
        req = Request(method=request.method, path=request.url.path,
                      headers={k.lower(): v for k, v in request.headers.items()},
                      query=dict(request.query_params), body=body,
                      client_ip=request.client.host if request.client else None)
        resp = await run_in_threadpool(dispatcher.handle, req)
        return JSONResponse(resp.body, status_code=resp.status, headers=resp.headers)

    async def openapi(_request: StarletteRequest) -> JSONResponse:
        return JSONResponse(spec)

    for route in router.routes:
        app.add_route(route.pattern, endpoint, methods=[route.method])
    if openapi_public:
        app.add_route("/openapi.json", openapi, methods=["GET"])
    return app
