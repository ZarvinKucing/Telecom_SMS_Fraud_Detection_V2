"""HTTP-level integration tests for the FastAPI adapter and in-memory API context."""
from __future__ import annotations

from datetime import UTC, datetime

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from fraud_engine.rules import DEFAULT_RULES
from tests.unit.api_fixtures import Api


@pytest.fixture
def api_client():
    # Avoid the slow end-to-end detector in transport tests; seed the same repository contract
    # with deterministic synthetic alert/component rows instead.
    api = Api(seed_alerts=False)
    window = datetime(2026, 1, 12, tzinfo=UTC)
    api.repo.save_detection(
        DEFAULT_RULES,
        pd.DataFrame([{"window_start": window, "entity_type": "destination",
                       "entity_key": "999129990001", "network": "NET_A",
                       "risk_score": 95.0, "band": "critical"}]),
        pd.DataFrame([{"window_start": window, "entity_type": "destination",
                       "entity_key": "999129990001", "network": "NET_A",
                       "rule_key": "repeated_destination", "rule_version": 1,
                       "severity": 0.9, "contribution": 0.54,
                       "evidence": {"count": 42}}]),
    )
    with TestClient(create_app(api.ctx, openapi_public=True)) as client:
        yield api, client


def bearer(api: Api, role: str, *, sub: str = "http-user") -> dict[str, str]:
    return {"Authorization": f"Bearer {api.token(role, sub=sub)}"}


def test_app_starts_and_public_health_and_openapi_work(api_client):
    _api, client = api_client
    assert client.get("/health").status_code == 200
    assert client.get("/health").json() == {"status": "ok"}
    spec = client.get("/openapi.json")
    assert spec.status_code == 200
    assert "/fraud/alerts" in spec.json()["paths"]
    assert "/openapi.json" in spec.json()["paths"]


def test_openapi_is_disabled_by_default():
    api = Api(seed_alerts=False)
    with TestClient(create_app(api.ctx)) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/openapi.json").status_code == 404


def test_app_lifespan_runs_pool_cleanup_on_shutdown():
    api = Api(seed_alerts=False)
    shutdown = []
    with TestClient(create_app(api.ctx, on_shutdown=lambda: shutdown.append(True), openapi_public=True)) as client:
        assert client.get("/health").status_code == 200
    assert shutdown == [True]


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Basic abc"},
                                      {"Authorization": "Bearer not-a-jwt"}])
def test_missing_or_malformed_authentication_is_generic_401(api_client, headers):
    _api, client = api_client
    response = client.get("/fraud/alerts", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    ("role", "path", "expected"),
    [
        ("administrator", "/fraud/summary", 200),
        ("administrator", "/fraud/alerts", 403),
        ("administrator", "/fraud/cases", 403),
        ("administrator", "/audit", 200),
        ("fraud_analyst", "/fraud/summary", 200),
        ("fraud_analyst", "/fraud/alerts", 200),
        ("fraud_analyst", "/fraud/cases", 200),
        ("fraud_analyst", "/audit", 403),
        ("security_analyst", "/fraud/summary", 403),
        ("security_analyst", "/fraud/alerts", 403),
        ("security_analyst", "/fraud/cases", 403),
        ("security_analyst", "/audit", 200),
        ("viewer", "/fraud/summary", 200),
        ("viewer", "/fraud/alerts", 403),
        ("viewer", "/fraud/cases", 403),
        ("viewer", "/audit", 403),
    ],
)
def test_http_role_permissions(api_client, role, path, expected):
    api, client = api_client
    response = client.get(path, headers=bearer(api, role))
    assert response.status_code == expected


def test_alert_list_detail_mask_identifiers_and_unmask_requires_permission(api_client):
    api, client = api_client
    headers = bearer(api, "fraud_analyst")
    listing = client.get("/fraud/alerts", headers=headers)
    assert listing.status_code == 200
    alert_id = listing.json()["items"][0]["alert_id"]
    detail = client.get(f"/fraud/alerts/{alert_id}", headers=headers)
    assert detail.status_code == 200
    assert "*****" in detail.json()["entity_key"]

    denied = client.get(f"/fraud/alerts/{alert_id}?unmask=true", headers=bearer(api, "viewer"))
    assert denied.status_code == 403
    assert api.repo.audit[-1]["action"] == "authz.denied"

    unmasked = client.get(f"/fraud/alerts/{alert_id}?unmask=true", headers=headers)
    assert unmasked.status_code == 200
    assert "*****" not in unmasked.json()["entity_key"]
    assert api.repo.audit[-1]["action"] == "msisdn.unmask"


def test_http_alert_ingestion_uses_the_isolated_record_store(api_client):
    api, client = api_client
    csv = ("message_id,received_time,source_addr,destination_addr,network\n"
           "msg-http-1,2026-01-12T10:00:00Z,SND001,999129990001,NET_A\n")
    response = client.post("/fraud/ingest", headers=bearer(api, "fraud_analyst"),
                           json={"file_name": "http.csv", "content": csv})
    assert response.status_code == 200
    assert response.json()["status"] == "loaded"
    assert response.json()["rows_loaded"] == 1
    assert len(api.store.records) == 1
    assert api.repo.audit[-1]["action"] == "ingest.upload"


def test_case_create_retrieve_update_lifecycle_and_audit_http(api_client):
    api, client = api_client
    headers = bearer(api, "fraud_analyst", sub="analyst-1")
    alert_id = api.alert_ids()[0]
    created = client.post("/fraud/cases", headers=headers, json={"alert_ids": [alert_id]})
    assert created.status_code == 201
    case_id = created.json()["case_id"]
    assert created.json()["alert_ids"] == [alert_id]

    fetched = client.get(f"/fraud/cases/{case_id}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["status"] == "New"

    triaged = client.post(f"/fraud/cases/{case_id}/transition", headers=headers,
                          json={"to_status": "Triaged"})
    assert triaged.status_code == 200
    investigating = client.post(f"/fraud/cases/{case_id}/transition", headers=headers,
                                json={"to_status": "Investigating"})
    assert investigating.status_code == 200
    assert investigating.json()["assignee_sub"] == "analyst-1"
    note = client.post(f"/fraud/cases/{case_id}/notes", headers=headers,
                       json={"body": "reviewed supporting records"})
    assert note.status_code == 201
    assert client.get(f"/fraud/cases/{case_id}", headers=headers).json()["notes"][0]["body"] == \
        "reviewed supporting records"
    for status in ("ConfirmedFraud", "Closed"):
        transition = client.post(f"/fraud/cases/{case_id}/transition", headers=headers,
                                 json={"to_status": status})
        assert transition.status_code == 200
    reopened = client.post(f"/fraud/cases/{case_id}/reopen", headers=headers,
                           json={"reason": "new carrier evidence received"})
    assert reopened.status_code == 200
    assert reopened.json()["status"] == "Investigating"

    audit_rows = client.get("/audit", headers=bearer(api, "administrator"))
    assert audit_rows.status_code == 200
    actions = {row["action"] for row in audit_rows.json()["items"]}
    assert {"case.create", "case.transition", "case.note"} <= actions
    verified = client.get("/audit/verify", headers=bearer(api, "security_analyst"))
    assert verified.status_code == 200
    assert verified.json()["ok"] is True


def test_http_validation_and_authorization_precede_validation(api_client):
    api, client = api_client
    analyst = bearer(api, "fraud_analyst")
    invalid = client.post("/fraud/cases", headers=analyst, json={"alert_ids": []})
    assert invalid.status_code == 422
    assert invalid.json()["error"] == "validation_error"

    denied = client.post("/fraud/cases", headers=bearer(api, "viewer"), json={"alert_ids": []})
    assert denied.status_code == 403

    malformed_json = client.post("/fraud/cases", headers={**analyst, "Content-Type": "application/json"},
                                 content=b"{")
    assert malformed_json.status_code == 400
    assert malformed_json.json() == {"error": "invalid_json"}

    # Transport-level JSON parsing precedes JWT/RBAC dispatch; semantic validation does not.
    malformed_without_auth = client.post("/fraud/cases", content=b"{")
    assert malformed_without_auth.status_code == 400


def test_http_body_limit_rejects_oversized_payload(api_client):
    api, client = api_client
    response = client.post("/fraud/ingest", headers=bearer(api, "fraud_analyst"),
                           json={"file_name": "large.csv", "content": "x" * 500_000})
    assert response.status_code == 413
    assert response.json() == {"error": "payload_too_large"}


def test_http_transaction_rolls_back_case_and_audit_failure(api_client, monkeypatch):
    api, client = api_client
    headers = bearer(api, "fraud_analyst")
    created = client.post("/fraud/cases", headers=headers, json={"alert_ids": [api.alert_ids()[0]]})
    assert created.status_code == 201
    case_id = created.json()["case_id"]
    before_events = len(api.repo.events)
    before_audit = api.repo.audit_count()
    append_audit = api.repo.append_audit

    def fail_transition(fields):
        if fields["action"] == "case.transition":
            raise RuntimeError("synthetic audit failure")
        return append_audit(fields)

    monkeypatch.setattr(api.repo, "append_audit", fail_transition)
    response = client.post(f"/fraud/cases/{case_id}/transition", headers=headers,
                           json={"to_status": "Triaged"})
    assert response.status_code == 500
    assert response.json() == {"error": "internal_error"}
    assert api.repo.get_case(case_id)["status"] == "New"
    assert len(api.repo.events) == before_events
    assert api.repo.audit_count() == before_audit
