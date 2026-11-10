"""RepoContract executed against its own disposable PostgreSQL database."""
from __future__ import annotations

import os
import unittest

from sqlalchemy import text

from backend.sql_repo import SqlRepo
from fraud_engine.pg_store import make_engine
from tests.unit.test_repo_contract import RepoContract

DATABASE_NAME = "fraud_sql_repo_it_20261109"
DATABASE_ROLE = "fraud_sql_repo_runner_20261109"
URL_ENV = "HTTP_SQL_CONTRACT_URL"


@unittest.skipUnless(os.environ.get(URL_ENV), f"set {URL_ENV} for isolated SQL Repo contract tests")
class SqlRepoIntegrationContract(RepoContract, unittest.TestCase):
    def make_repo(self):
        engine = make_engine(os.environ[URL_ENV])
        if engine.url.database != DATABASE_NAME or engine.url.username != DATABASE_ROLE:
            engine.dispose()
            raise ValueError("SQL Repo contract tests require their exact dedicated database and role")
        with engine.connect() as conn:
            identity = conn.execute(text("SELECT current_database(), current_user")).one()
            revision = conn.execute(text("SELECT version_num FROM public.alembic_version")).scalar_one()
        if identity != (DATABASE_NAME, DATABASE_ROLE) or revision != "0002":
            engine.dispose()
            raise ValueError("SQL Repo contract test database identity or revision mismatch")

        # Alembic already created the schema. This test reset is guarded by the exact database identity.
        with engine.begin() as conn:
            identity = conn.execute(text("SELECT current_database(), current_user")).one()
            if identity != (DATABASE_NAME, DATABASE_ROLE):
                engine.dispose()
                raise ValueError("refusing contract cleanup on an unexpected database")
            conn.execute(text("TRUNCATE audit_log, case_notes, case_events, risk_score_components, fraud_alerts, "
                              "fraud_cases, fraud_rules, user_refs, rejected_rows, sms_records, ingest_batches "
                              "RESTART IDENTITY CASCADE"))
        self.addCleanup(engine.dispose)
        return SqlRepo(engine)
