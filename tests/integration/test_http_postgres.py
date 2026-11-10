"""PostgreSQL-backed FastAPI integration tests. Requires HTTP_TEST_DATABASE_URL."""
from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import pandas as pd
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url

from backend.app import create_app
from backend.auth.testing import AUDIENCE, ISSUER, TestKeyPair, make_token
from backend.auth.tokens import verify_token
from backend.core import AppContext
from backend.sql_repo import SqlRepo
from fraud_engine.pg_store import PostgresStore
from fraud_engine.rules import DEFAULT_RULES

DATABASE_NAME = "fraud_http_it_recheck_20261109"
DATABASE_ROLE = "fraud_http_it_recheck_runner_20261109"
_URL_ENV = "HTTP_TEST_DATABASE_URL"
_KEYS = TestKeyPair.generate()


def _assert_database_identity(engine: Engine) -> None:
    """Fail closed unless every setup or HTTP operation is on this test database and role."""
    with engine.connect() as conn:
        identity = conn.execute(text("SELECT current_database(), current_user")).one()
    if identity != (DATABASE_NAME, DATABASE_ROLE):
        raise AssertionError("PostgreSQL integration test identity mismatch")


def _checked_request(client: TestClient, engine: Engine, method: str, path: str, **kwargs: Any):
    # Authenticated GETs upsert user_refs, so identity is checked for every request with a token.
    headers = kwargs.get("headers") or {}
    if method.upper() not in {"GET", "HEAD", "OPTIONS"} or any(k.lower() == "authorization" for k in headers):
        _assert_database_identity(engine)
    response = client.request(method, path, **kwargs)
    if method.upper() not in {"GET", "HEAD", "OPTIONS"} or any(k.lower() == "authorization" for k in headers):
        _assert_database_identity(engine)
    return response


class GuardedClient:
    def __init__(self, client: TestClient, engine: Engine) -> None:
        self._client, self._engine = client, engine

    def get(self, path: str, **kwargs: Any):
        return _checked_request(self._client, self._engine, "GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any):
        return _checked_request(self._client, self._engine, "POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any):
        return _checked_request(self._client, self._engine, "PUT", path, **kwargs)


def _headers(role: str = "fraud_analyst", sub: str = "http-pg-analyst") -> dict[str, str]:
    token = make_token(_KEYS.private_pem, sub, [role])
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def pg_engine():
    raw_url = os.environ.get(_URL_ENV)
    if not raw_url:
        pytest.skip(f"set {_URL_ENV} to run isolated PostgreSQL HTTP tests")
    url = make_url(raw_url)
    if url.database != DATABASE_NAME or url.username != DATABASE_ROLE:
        pytest.fail("HTTP PostgreSQL tests require the dedicated database and role")
    engine = create_engine(url, pool_pre_ping=True)
    try:
        _assert_database_identity(engine)
        with engine.connect() as conn:
            revision = conn.execute(text("SELECT version_num FROM public.alembic_version")).scalar_one()
        if revision != "0002":
            pytest.fail("HTTP PostgreSQL test database must be at Alembic revision 0002")
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def postgres_http(pg_engine: Engine):
    _assert_database_identity(pg_engine)
    with pg_engine.begin() as conn:
        conn.execute(text("TRUNCATE audit_log, case_notes, case_events, risk_score_components, fraud_alerts, "
                           "fraud_cases, fraud_rules, user_refs, rejected_rows, sms_records, ingest_batches "
                           "RESTART IDENTITY CASCADE"))

    repo = SqlRepo(pg_engine)
    for rule in DEFAULT_RULES:
        _assert_database_identity(pg_engine)
        with repo.transaction():
            repo.add_rule_version(rule.rule_key, rule.rule_type, dict(rule.params), rule.weight, rule.enabled)

    window = datetime(2026, 1, 12, tzinfo=UTC)
    alerts = pd.DataFrame([{"window_start": window, "entity_type": "destination",
                            "entity_key": "999129990001", "network": "NET_A",
                            "risk_score": 95.0, "band": "critical"}])
    components = pd.DataFrame([{"window_start": window, "entity_type": "destination",
                                "entity_key": "999129990001", "network": "NET_A",
                                "rule_key": "repeated_destination", "rule_version": 1,
                                "severity": 0.9, "contribution": 0.54,
                                "evidence": {"count": 42}}])
    _assert_database_identity(pg_engine)
    with repo.transaction():
        repo.save_detection(DEFAULT_RULES, alerts, components)

    ctx = AppContext(
        repo=repo,
        store=PostgresStore(pg_engine, repo.current_connection),
        verify=lambda token: verify_token(token, lambda _token: _KEYS.public_pem, ISSUER, AUDIENCE),
        max_ingest_bytes=200_000,
    )
    with TestClient(create_app(ctx)) as raw_client:
        yield pg_engine, repo, GuardedClient(raw_client, pg_engine)


def test_postgres_http_ingestion_alert_case_and_audit(postgres_http):
    engine, repo, client = postgres_http
    headers = _headers()

    alert_list = client.get("/fraud/alerts", headers=headers)
    assert alert_list.status_code == 200
    alert_id = alert_list.json()["items"][0]["alert_id"]
    assert "*****" in alert_list.json()["items"][0]["entity_key"]
    detail = client.get(f"/fraud/alerts/{alert_id}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["components"][0]["evidence"] == {"count": 42}
    denied = client.get(f"/fraud/alerts/{alert_id}", headers=_headers("viewer"))
    assert denied.status_code == 403

    csv = ("message_id,received_time,source_addr,destination_addr,network\n"
           "pg-http-1,2026-01-12T10:00:00Z,SND001,999129990001,NET_A\n")
    ingested = client.post("/fraud/ingest", headers=headers,
                           json={"file_name": "pg-http.csv", "content": csv})
    assert ingested.status_code == 200
    assert ingested.json()["rows_loaded"] == 1
    with engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM sms_records WHERE message_id='pg-http-1'")).scalar_one() == 1
        assert conn.execute(text("SELECT COUNT(*) FROM ingest_batches WHERE file_name='pg-http.csv'")).scalar_one() == 1

    created = client.post("/fraud/cases", headers=headers, json={"alert_ids": [alert_id]})
    assert created.status_code == 201
    case_id = created.json()["case_id"]
    for status in ("Triaged", "Investigating", "ConfirmedFraud", "Closed"):
        moved = client.post(f"/fraud/cases/{case_id}/transition", headers=headers,
                            json={"to_status": status})
        assert moved.status_code == 200
    reopened = client.post(f"/fraud/cases/{case_id}/reopen", headers=headers,
                           json={"reason": "new carrier evidence received"})
    assert reopened.status_code == 200
    assert reopened.json()["status"] == "Investigating"

    audit_rows = client.get("/audit", headers=_headers("administrator"))
    assert audit_rows.status_code == 200
    actions = {row["action"] for row in audit_rows.json()["items"]}
    assert {"authz.denied", "ingest.upload", "case.create", "case.transition", "case.reopen"} <= actions
    verified = client.get("/audit/verify", headers=_headers("security_analyst"))
    assert verified.status_code == 200
    assert verified.json()["ok"] is True
    assert repo.get_case(case_id)["status"] == "Investigating"
    _assert_database_identity(engine)


def test_postgres_http_rolls_back_ingestion_and_case_on_audit_failure(postgres_http, monkeypatch):
    engine, repo, client = postgres_http
    headers = _headers()
    original_append = repo.append_audit

    def fail_ingest(fields):
        if fields["action"] == "ingest.upload":
            raise RuntimeError("synthetic audit write failure")
        return original_append(fields)

    monkeypatch.setattr(repo, "append_audit", fail_ingest)
    csv = ("message_id,received_time,source_addr,destination_addr,network\n"
           "pg-rollback-1,2026-01-12T11:00:00Z,SND002,999129990002,NET_A\n")
    failed_ingest = client.post("/fraud/ingest", headers=headers,
                                json={"file_name": "rollback.csv", "content": csv})
    assert failed_ingest.status_code == 500
    with engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM ingest_batches WHERE file_name='rollback.csv'")).scalar_one() == 0
        assert conn.execute(text("SELECT COUNT(*) FROM sms_records WHERE message_id='pg-rollback-1'")).scalar_one() == 0
        assert conn.execute(text("SELECT COUNT(*) FROM audit_log WHERE action='ingest.upload'")).scalar_one() == 0

    monkeypatch.setattr(repo, "append_audit", original_append)
    alert_id = client.get("/fraud/alerts", headers=headers).json()["items"][0]["alert_id"]
    created = client.post("/fraud/cases", headers=headers, json={"alert_ids": [alert_id]})
    assert created.status_code == 201
    case_id = created.json()["case_id"]
    before_audits = repo.audit_count()

    def fail_transition(fields):
        if fields["action"] == "case.transition":
            raise RuntimeError("synthetic audit write failure")
        return original_append(fields)

    monkeypatch.setattr(repo, "append_audit", fail_transition)
    failed_transition = client.post(f"/fraud/cases/{case_id}/transition", headers=headers,
                                   json={"to_status": "Triaged"})
    assert failed_transition.status_code == 500
    case = repo.get_case(case_id)
    assert case["status"] == "New"
    assert [event["to_status"] for event in case["events"]] == ["New"]
    assert repo.audit_count() == before_audits
    _assert_database_identity(engine)
