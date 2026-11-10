"""One behavioural contract, run against every Repo implementation.

MemoryRepo always runs. SqlRepo runs only when TEST_DATABASE_URL targets the disposable PostgreSQL database
named exactly `fraud_test` (contract tables are truncated between tests) and SQLAlchemy is installed:

    docker compose up -d postgres
    createdb fraud_test        # then:
    TEST_DATABASE_URL=postgresql+psycopg://USER:PASS@localhost:5432/fraud_test pytest tests/unit/test_repo_contract.py
"""
import os
import unittest
from datetime import UTC, datetime, timedelta

from backend.errors import ConflictError, NotFoundError
from backend.memory_repo import MemoryRepo
from backend.services import audit
from fraud_engine.anomaly import AnomalyConfig, RULE_KEY, as_rule_record
from fraud_engine.rules import DEFAULT_RULES
from tests.unit.api_fixtures import _detection

T0 = datetime(2026, 1, 12, 9, 0, tzinfo=UTC)


def require_fraud_test_database(database_name):
    if database_name != "fraud_test":
        raise ValueError("destructive SQL contract tests require database name exactly 'fraud_test'")


def require_fraud_test_identity(url_database, current_database):
    require_fraud_test_database(url_database)
    require_fraud_test_database(current_database)


class RepoContract:
    def make_repo(self):
        raise NotImplementedError

    def setUp(self):
        self.repo = self.make_repo()
        res = _detection()[2]
        self.metadata = [*DEFAULT_RULES, as_rule_record(AnomalyConfig())]
        self.repo.save_detection(self.metadata, res.alerts, res.components)
        for r in DEFAULT_RULES:
            if self.repo.get_latest_rule(r.rule_key) is None:
                self.repo.add_rule_version(r.rule_key, r.rule_type, dict(r.params), r.weight, True)

    def ids(self):
        return [a["alert_id"] for a in self.repo.list_alerts(band=None, network=None, entity_type=None, limit=50, offset=0)[0]]

    def test_alerts_listed_by_score_with_total_filter_and_paging(self):
        rows, total = self.repo.list_alerts(band=None, network=None, entity_type=None, limit=50, offset=0)
        self.assertEqual(total, 3)
        self.assertEqual([r["risk_score"] for r in rows], sorted((r["risk_score"] for r in rows), reverse=True))
        page, total2 = self.repo.list_alerts(band=None, network=None, entity_type=None, limit=1, offset=1)
        self.assertEqual((len(page), total2, page[0]["alert_id"]), (1, 3, rows[1]["alert_id"]))
        only, n = self.repo.list_alerts(band=None, network="NET_A", entity_type="destination", limit=50, offset=0)
        self.assertEqual((n, only[0]["entity_type"]), (1, "destination"))

    def test_alert_detail_has_components_with_versions_and_evidence(self):
        a = next(r for r in self.repo.list_alerts(band=None, network=None, entity_type="sender", limit=5, offset=0)[0])
        detail = self.repo.get_alert(a["alert_id"])
        keys = {c["rule_key"] for c in detail["components"]}
        self.assertIn("spiking_sender", keys)
        anomaly = next(c for c in detail["components"] if c["rule_key"] == RULE_KEY)
        expected = _detection()[2].components
        match = expected[
            (expected["window_start"] == a["window_start"])
            & (expected["network"] == a["network"])
            & (expected["entity_type"] == a["entity_type"])
            & (expected["entity_key"] == a["entity_key"])
            & (expected["rule_key"] == RULE_KEY)
        ].iloc[0]
        self.assertEqual(anomaly["rule_version"], 1)
        self.assertEqual(anomaly["evidence"], match["evidence"])
        self.assertTrue(all(c["rule_version"] == 1 and isinstance(c["evidence"], dict) for c in detail["components"]))
        self.assertIsNone(self.repo.get_alert(999999))

    def test_auxiliary_metadata_persists_without_entering_configurable_registry(self):
        anomaly = self.repo.get_rule_metadata(RULE_KEY, 1)
        self.assertEqual(anomaly["rule_key"], RULE_KEY)
        self.assertEqual(anomaly["version"], 1)
        self.assertEqual(anomaly["rule_type"], "anomaly_model")
        self.assertEqual(anomaly["params"], as_rule_record(AnomalyConfig()).params)
        configurable = {r["rule_key"]: r for r in self.repo.list_rules()}
        self.assertEqual(set(configurable), {r.rule_key for r in DEFAULT_RULES})
        self.assertNotIn(RULE_KEY, configurable)
        self.assertIsNone(self.repo.get_latest_rule(RULE_KEY))
        for rule in DEFAULT_RULES:
            persisted = self.repo.get_rule_metadata(rule.rule_key, rule.version)
            self.assertEqual(
                (persisted["version"], persisted["rule_type"], persisted["params"],
                 persisted["weight"], persisted["enabled"]),
                (rule.version, rule.rule_type, rule.params, rule.weight, rule.enabled),
            )

    def test_save_detection_is_idempotent_and_keeps_case_links(self):
        before = self.ids()
        cid = self.repo.create_case(priority="P2", opened_by="u", alert_ids=[before[0]], now=T0)["case_id"]
        res = _detection()[2]
        metadata_before = {
            (rule.rule_key, rule.version): self.repo.get_rule_metadata(rule.rule_key, rule.version)
            for rule in self.metadata
        }
        details_before = {
            aid: {
                (component["rule_key"], component["rule_version"]): component["evidence"]
                for component in self.repo.get_alert(aid)["components"]
            }
            for aid in before
        }
        self.repo.save_detection(self.metadata, res.alerts, res.components)
        self.assertEqual(sorted(self.ids()), sorted(before))
        self.assertEqual(self.repo.get_alert(before[0])["case_id"], cid)
        metadata_after = {
            key: self.repo.get_rule_metadata(*key) for key in metadata_before
        }
        details_after = {
            aid: {
                (component["rule_key"], component["rule_version"]): component["evidence"]
                for component in self.repo.get_alert(aid)["components"]
            }
            for aid in before
        }
        self.assertEqual(metadata_after, metadata_before)
        self.assertEqual(details_after, details_before)

    def test_components_without_metadata_are_rejected_before_writes(self):
        result = _detection()[2]
        before = self.ids()
        with self.assertRaisesRegex(ValueError, "missing metadata.*anomaly_isolation_forest"):
            self.repo.save_detection(DEFAULT_RULES, result.alerts, result.components)
        self.assertEqual(sorted(self.ids()), sorted(before))

    def test_summary_counts(self):
        s = self.repo.alert_summary()
        self.assertEqual(s["alerts_total"], 3)
        self.assertEqual(sum(s["alerts_by_band"].values()), 3)
        self.assertEqual(set(s["alerts_by_band"]), {"low", "medium", "high", "critical"})

    def test_rules_are_versioned_never_overwritten(self):
        v2 = self.repo.add_rule_version("repeated_destination", "repeated_destination", {"threshold": 40}, 0.7, True)
        self.assertEqual(v2["version"], 2)
        latest = {r["rule_key"]: r for r in self.repo.list_rules()}
        self.assertEqual((latest["repeated_destination"]["version"], latest["repeated_destination"]["params"]),
                         (2, {"threshold": 40}))
        self.assertEqual(len(latest), 3)
        self.assertEqual(self.repo.get_latest_rule("repeated_destination")["weight"], 0.7)
        self.assertIsNone(self.repo.get_latest_rule("nope"))

    def test_case_lifecycle_rows(self):
        a, b = self.ids()[:2]
        case = self.repo.create_case(priority="P1", opened_by="alice", alert_ids=[a, b], now=T0)
        cid = case["case_id"]
        self.repo.add_case_event(cid, None, "New", "alice", T0, None)
        self.repo.set_case_state(cid, "Investigating", "alice", None, None)
        self.repo.add_case_event(cid, "New", "Investigating", "alice", T0 + timedelta(seconds=1), "go")
        note = self.repo.add_case_note(cid, "alice", "hello", T0)
        got = self.repo.get_case(cid, for_update=True)
        self.assertEqual((got["status"], got["assignee_sub"], got["alert_ids"]), ("Investigating", "alice", sorted([a, b])))
        self.assertEqual([e["to_status"] for e in got["events"]], ["New", "Investigating"])
        self.assertEqual([n["id"] for n in got["notes"]], [note["id"]])
        self.assertEqual(self.repo.case_status_counts(), {"Investigating": 1})
        self.assertEqual(self.repo.list_cases(status="Investigating", limit=10, offset=0)[1], 1)
        self.assertEqual(self.repo.list_cases(status="Closed", limit=10, offset=0)[1], 0)
        self.assertIsNone(self.repo.get_case(424242))

    def test_alert_cannot_be_linked_twice_and_failure_links_nothing(self):
        a, b = self.ids()[:2]
        self.repo.create_case(priority="P2", opened_by="u", alert_ids=[b], now=T0)
        with self.assertRaises(ConflictError), self.repo.transaction():
            self.repo.create_case(priority="P2", opened_by="u", alert_ids=[a, b], now=T0)
        self.assertIsNone(self.repo.get_alert(a)["case_id"])
        self.assertEqual(self.repo.case_status_counts(), {"New": 1})
        with self.assertRaises(NotFoundError):
            self.repo.create_case(priority="P2", opened_by="u", alert_ids=[a, 999999], now=T0)

    def test_transaction_rolls_back_everything_on_error(self):
        a = self.ids()[0]
        audits = self.repo.audit_count()
        with self.assertRaises(RuntimeError), self.repo.transaction():
            self.repo.create_case(priority="P2", opened_by="u", alert_ids=[a], now=T0)
            self.repo.append_audit(self._entry("x"))
            raise RuntimeError("boom")
        self.assertEqual((self.repo.case_status_counts(), self.repo.audit_count(), self.repo.get_alert(a)["case_id"]),
                         ({}, audits, None))

    def test_transaction_commits_on_success(self):
        a = self.ids()[0]
        with self.repo.transaction():
            self.repo.create_case(priority="P2", opened_by="u", alert_ids=[a], now=T0)
        self.assertEqual(self.repo.case_status_counts(), {"New": 1})

    def test_detection_write_joins_repository_transaction(self):
        before = self.repo.list_alerts(band=None, network=None, entity_type=None, limit=50, offset=0)[0]
        result = _detection()[2]
        changed = result.alerts.copy()
        changed.loc[changed.index[0], "risk_score"] = 1.0
        with self.assertRaises(RuntimeError), self.repo.transaction():
            self.repo.save_detection(self.metadata, changed, result.components)
            raise RuntimeError("rollback detection write")
        after = self.repo.list_alerts(band=None, network=None, entity_type=None, limit=50, offset=0)[0]
        self.assertEqual({r["alert_id"]: r["risk_score"] for r in before},
                         {r["alert_id"]: r["risk_score"] for r in after})

    def _entry(self, action, details=None):
        return {"at": T0, "actor_sub": "u", "action": action, "resource_type": "t", "resource_id": "1",
                "outcome": "success", "source_ip": "10.0.0.1", "details": details or {}}

    def test_audit_chain_links_verifies_and_lists_newest_first(self):
        base = self.repo.audit_count()
        r1 = self.repo.append_audit(self._entry("a", {"k": [1, 2], "nested": {"z": 1, "a": None}}))
        r2 = self.repo.append_audit(self._entry("b"))
        self.assertEqual(r2["prev_hash"], r1["row_hash"])
        rows = self.repo.iter_audit()
        self.assertEqual(len(rows), base + 2)
        self.assertEqual(rows[0]["prev_hash"], audit.GENESIS)
        self.assertTrue(audit.verify_chain(rows).ok, "stored rows must re-hash identically after a round trip")
        listed, total = self.repo.list_audit(limit=1, offset=0)
        self.assertEqual((listed[0]["action"], total), ("b", base + 2))

    def test_user_ref_upsert_updates_username(self):
        self.repo.upsert_user_ref("sub-1", "alice", T0)
        self.repo.upsert_user_ref("sub-1", "alice2", T0 + timedelta(seconds=5))  # must not raise


class MemoryRepoContract(RepoContract, unittest.TestCase):
    def make_repo(self):
        return MemoryRepo()


class DatabaseSafetyTests(unittest.TestCase):
    def test_only_exact_fraud_test_name_is_allowed(self):
        require_fraud_test_database("fraud_test")
        for name in ("fraud_platform", "fraud_platform_test", "my_fraud_test", "test"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                require_fraud_test_database(name)

    def test_actual_server_database_must_match_the_exact_test_target(self):
        require_fraud_test_identity("fraud_test", "fraud_test")
        for actual in ("fraud_platform", "fraud_migration_test", "another_db"):
            with self.subTest(actual=actual), self.assertRaises(ValueError):
                require_fraud_test_identity("fraud_test", actual)


_DB_URL = os.environ.get("TEST_DATABASE_URL")
try:
    import sqlalchemy  # noqa: F401
    _HAVE_SA = True
except ImportError:
    _HAVE_SA = False


@unittest.skipUnless(_DB_URL and _HAVE_SA, "set TEST_DATABASE_URL (disposable *test* DB) and install SQLAlchemy")
class SqlRepoContract(RepoContract, unittest.TestCase):
    def make_repo(self):
        from sqlalchemy import text

        from backend.sql_repo import SqlRepo
        from common.db.models import Base
        from fraud_engine.pg_store import make_engine
        engine = make_engine(_DB_URL)
        with engine.begin() as c:
            current_database = c.execute(text("SELECT current_database()")).scalar_one()
            require_fraud_test_identity(engine.url.database, current_database)
            Base.metadata.create_all(c)
            current_database = c.execute(text("SELECT current_database()")).scalar_one()
            require_fraud_test_identity(engine.url.database, current_database)
            c.execute(text("TRUNCATE audit_log, case_notes, case_events, risk_score_components, fraud_alerts, "
                           "fraud_cases, fraud_rules, user_refs RESTART IDENTITY CASCADE"))
        self.addCleanup(engine.dispose)
        return SqlRepo(engine)


if __name__ == "__main__":
    unittest.main()
