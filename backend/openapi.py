"""OpenAPI document generated from the route table, so the docs cannot drift from enforced permissions."""
from __future__ import annotations

import re
from typing import Any

from backend.core import PUBLIC, Router


def build_spec(router: Router, title: str = "Fraud & Security Platform API", version: str = "0.2.0",
               *, openapi_public: bool = False) -> dict[str, Any]:
    paths: dict[str, dict[str, Any]] = {}
    for r in router.routes:
        success_code = "201" if r.method == "POST" and r.pattern in {"/fraud/cases", "/fraud/cases/{case_id}/notes"} else "200"
        responses: dict[str, Any] = {
            success_code: {"description": "Created" if success_code == "201" else "Success"},
            "400": {"description": "Malformed JSON request body"},
            "405": {"description": "Method not allowed for this path"},
            "413": {"description": "Request body exceeds the configured limit"},
            "500": {"description": "Unexpected server error"},
        }
        if (r.pattern in {"/fraud/alerts/{alert_id}", "/fraud/rules/{rule_key}", "/fraud/cases",
                          "/fraud/cases/{case_id}", "/fraud/cases/{case_id}/transition",
                          "/fraud/cases/{case_id}/reopen", "/fraud/cases/{case_id}/notes"}):
            responses["404"] = {"description": "Requested resource was not found"}
        op: dict[str, Any] = {
            "summary": r.summary,
            "operationId": f"{r.method.lower()}_{re.sub(r'[^a-z0-9]+', '_', r.pattern.lower()).strip('_')}",
            "x-required-permission": r.permission,
            "parameters": [{"name": n, "in": "path", "required": True, "schema": {"type": "string"}}
                           for n in re.findall(r"\{(\w+)\}", r.pattern)],
            "responses": responses,
        }
        if r.permission != PUBLIC:
            op["security"] = [{"bearerAuth": []}]
            op["responses"]["401"] = {"description": "Missing or invalid token"}
            op["responses"]["403"] = {"description": "Authenticated but not permitted (audited)"}
        if r.method == "POST" and r.pattern == "/fraud/ingest":
            op["responses"]["422"] = {"description": "Invalid request or CSV schema"}
            op["responses"]["502"] = {"description": "Ingestion failed"}
        elif r.validator:
            op["responses"]["422"] = {"description": "Request validation failed"}
        if r.method == "POST" and r.pattern == "/fraud/cases":
            op["responses"]["409"] = {"description": "Case state conflict or alert already linked"}
        if r.pattern in {"/fraud/cases/{case_id}/transition", "/fraud/cases/{case_id}/reopen"}:
            op["responses"]["409"] = {"description": "State conflict or requested resource conflict"}
        if r.writes:
            op["x-audited"] = True
        paths.setdefault(r.pattern, {})[r.method.lower()] = op
    if openapi_public:
        paths["/openapi.json"] = {"get": {
            "summary": "OpenAPI schema (enabled only in development or test)",
            "operationId": "get_openapi_json",
            "x-required-permission": "public_development_only",
            "responses": {"200": {"description": "OpenAPI 3.0 schema"}},
        }}
    return {"openapi": "3.0.3", "info": {"title": title, "version": version}, "paths": paths,
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer",
                                                              "bearerFormat": "JWT"}}}}
