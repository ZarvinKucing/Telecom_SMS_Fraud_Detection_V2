import unittest

from backend.core import Dispatcher, Request, Router
from backend.handlers import router
from backend.services import audit
from tests.unit.api_fixtures import ROLES, Api

CSV_OK = None


def _csv():
    global CSV_OK
    if CSV_OK is None:
        from synthetic_data.generate_cdr import GeneratorConfig, generate_cdr
        CSV_OK = generate_cdr(GeneratorConfig(seed=3, days=1)).records.head(50).to_csv(index=False)
    return CSV_OK


def _routes(api):
    """(method, pattern) -> (allowed roles, success status, builder -> (path, query, body))."""
    fraud, admin_sec = {"fraud_analyst"}, {"administrator", "security_analyst"}
    first_alert = lambda a: a.alert_ids()[0]  # noqa: E731
    return {
        ("GET", "/health"): (set(ROLES), 200, lambda: ("/health", None, None)),
        ("GET", "/fraud/summary"): ({"administrator", "fraud_analyst", "viewer"}, 200,
                                    lambda: ("/fraud/summary", None, None)),
        ("GET", "/fraud/alerts"): (fraud, 200, lambda: ("/fraud/alerts", None, None)),
        ("GET", "/fraud/alerts/{alert_id}"): (fraud, 200, lambda: (f"/fraud/alerts/{first_alert(api)}", None, None)),
        ("GET", "/fraud/rules"): ({"administrator", "fraud_analyst"}, 200, lambda: ("/fraud/rules", None, None)),
        ("PUT", "/fraud/rules/{rule_key}"): (fraud, 200, lambda: (
            "/fraud/rules/repeated_destination", None,
            {"params": {"threshold": 30}, "weight": 0.5, "enabled": True})),
        ("POST", "/fraud/ingest"): (fraud, 200, lambda: ("/fraud/ingest", None,
                                                          {"file_name": "x.csv", "content": _csv()})),
        ("POST", "/fraud/cases"): (fraud, 201, lambda: ("/fraud/cases", None, {"alert_ids": [first_alert(api)]})),
        ("GET", "/fraud/cases"): (fraud, 200, lambda: ("/fraud/cases", None, None)),
        ("GET", "/fraud/cases/{case_id}"): (fraud, 200, lambda: (f"/fraud/cases/{api.new_case()}", None, None)),
        ("POST", "/fraud/cases/{case_id}/transition"): (fraud, 200, lambda: (
            f"/fraud/cases/{api.new_case()}/transition", None, {"to_status": "Triaged"})),
        ("POST", "/fraud/cases/{case_id}/reopen"): (fraud, 409, lambda: (  # open case: valid request, wrong state
            f"/fraud/cases/{api.new_case()}/reopen", None, {"reason": "need to look again"})),
        ("POST", "/fraud/cases/{case_id}/notes"): (fraud, 201, lambda: (
            f"/fraud/cases/{api.new_case()}/notes", None, {"body": "checked the sender"})),
        ("GET", "/audit"): (admin_sec, 200, lambda: ("/audit", None, None)),
        ("GET", "/audit/verify"): (admin_sec, 200, lambda: ("/audit/verify", None, None)),
    }


class AuthorizationMatrixTests(unittest.TestCase):
    def test_every_registered_route_is_covered_by_the_matrix(self):
        covered = set(_routes(Api(seed_alerts=False)))
        registered = {(r.method, r.pattern) for r in router.routes}
        self.assertEqual(registered, covered, "add new routes to the authorization matrix test")

    def test_every_route_for_every_role(self):
        for (method, pattern), (allowed, ok_status, _build) in _routes(Api()).items():
            for role in ROLES:
                api = Api()  # fresh state per call so one role's request cannot affect another's
                path, query, body = _rebuild(api, method, pattern)
                resp = api.call(method, path, role, query=query, body=body)
                want = ok_status if role in allowed else 403
                self.assertEqual(resp.status, want, f"{method} {pattern} as {role}: {resp.body}")

    def test_no_token_is_401_on_every_protected_route(self):
        api = Api()
        for r in router.routes:
            if r.permission == "public":
                continue
            path = r.pattern.replace("{alert_id}", "1").replace("{case_id}", "1").replace("{rule_key}", "x")
            resp = api.call(r.method, path)
            self.assertEqual(resp.status, 401, r.pattern)
            self.assertEqual(resp.headers.get("WWW-Authenticate"), "Bearer")

    def test_only_health_is_public(self):
        self.assertEqual([r.pattern for r in router.routes if r.permission == "public"], ["/health"])
        self.assertTrue(all(r.permission for r in router.routes))

    def test_unknown_path_and_method(self):
        api = Api()
        self.assertEqual(api.call("GET", "/nope", "fraud_analyst").status, 404)
        self.assertEqual(api.call("DELETE", "/fraud/alerts", "fraud_analyst").status, 405)

    def test_token_with_no_known_roles_gets_nothing(self):
        api = Api()
        self.assertEqual(api.call("GET", "/fraud/summary", "intern").status, 403)

    def test_multi_role_user_gets_union(self):
        api = Api()
        self.assertEqual(api.call("GET", "/audit", "viewer", "security_analyst").status, 200)
        self.assertEqual(api.call("GET", "/fraud/alerts", "viewer", "security_analyst").status, 403)


def _rebuild(api, method, pattern):
    return _routes(api)[(method, pattern)][2]()


class DenialAndFailureTests(unittest.TestCase):
    def test_403_is_audited_with_actor_and_required_permission(self):
        api = Api()
        api.call("GET", "/fraud/alerts", "viewer", sub="mallory")
        row = api.repo.audit[-1]
        self.assertEqual((row["action"], row["actor_sub"], row["outcome"]), ("authz.denied", "mallory", "denied"))
        self.assertEqual(row["details"], {"required": "fraud:alert:read"})
        self.assertEqual(api.events[-1]["kind"], "authz.denied")

    def test_401_is_not_written_to_the_audit_table_but_reaches_the_event_sink(self):
        api = Api()
        before = len(api.repo.audit)
        api.call("GET", "/fraud/alerts", token="garbage")
        self.assertEqual(len(api.repo.audit), before)
        self.assertEqual(api.events[-1]["kind"], "authn.failed")

    def test_401_does_not_reveal_why(self):
        api = Api()
        self.assertEqual(api.call("GET", "/fraud/alerts", token="garbage").body, {"error": "unauthorized"})

    def test_unexpected_error_is_generic_500_without_detail(self):
        api = Api()
        api.repo.list_alerts = lambda **kw: (_ for _ in ()).throw(RuntimeError("secret db password=hunter2"))
        r = api.call("GET", "/fraud/alerts", "fraud_analyst")
        self.assertEqual((r.status, r.body), (500, {"error": "internal_error"}))

    def test_state_changing_route_without_audit_row_is_rolled_back(self):
        api = Api()
        rogue = Router()

        @rogue.add("POST", "/rogue", "fraud:rules:write", writes=True)
        def handler(ctx, p, req, d):
            ctx.repo.add_rule_version("rogue", "repeated_destination", {"threshold": 5}, 0.5, True)
            return 200, {}

        resp = Dispatcher(api.ctx, rogue).handle(Request("POST", "/rogue", {"authorization": "Bearer " + api.token("fraud_analyst")}))
        self.assertEqual(resp.status, 500)
        self.assertIsNone(api.repo.get_latest_rule("rogue"))

    def test_every_state_changing_route_writes_an_audit_row(self):
        for r in router.routes:
            if not r.writes:
                continue
            api = Api()
            path, query, body = _rebuild(api, r.method, r.pattern)
            before = len(api.repo.audit)
            resp = api.call(r.method, path, "fraud_analyst", query=query, body=body)
            if resp.status < 400:
                self.assertGreater(len(api.repo.audit), before, r.pattern)


class AlertAndMaskingTests(unittest.TestCase):
    def test_list_is_masked_and_never_exposes_full_numbers(self):
        api = Api()
        body = api.call("GET", "/fraud/alerts", "fraud_analyst").body
        text = str(body)
        self.assertNotIn("999129990001", text)
        self.assertIn("99912*****01", text)
        self.assertEqual(body["total"], 3)  # the anomaly hit merges into the spiking sender alert, no extra alert

    def test_detail_masked_by_default_unmask_is_audited(self):
        api = Api()
        dest = next(r for r in api.repo.alerts.values() if r["entity_type"] == "destination")["alert_id"]
        masked = api.call("GET", f"/fraud/alerts/{dest}", "fraud_analyst").body
        self.assertNotIn("999129990001", str(masked))
        before = len(api.repo.audit)
        full = api.call("GET", f"/fraud/alerts/{dest}", "fraud_analyst", query={"unmask": "true"}).body
        self.assertEqual(full["entity_key"], "999129990001")
        row = api.repo.audit[-1]
        self.assertEqual((row["action"], row["resource_id"], len(api.repo.audit)), ("msisdn.unmask", str(dest), before + 1))
        self.assertNotIn("999129990001", str(row))  # the audit row never stores the number

    def test_unmask_requires_its_own_permission_even_with_alert_read(self):
        from backend.auth import permissions
        api = Api()
        original = permissions.PERMISSIONS["fraud_analyst"]
        permissions.PERMISSIONS["fraud_analyst"] = original - {"fraud:msisdn:unmask"}
        try:
            self.assertEqual(api.call("GET", "/fraud/alerts/1", "fraud_analyst").status, 200)
            self.assertEqual(api.call("GET", "/fraud/alerts/1", "fraud_analyst", query={"unmask": "true"}).status, 403)
            self.assertEqual(api.repo.audit[-1]["details"], {"required": "fraud:msisdn:unmask"})
        finally:
            permissions.PERMISSIONS["fraud_analyst"] = original

    def test_filters_and_paging(self):
        api = Api()
        page = api.call("GET", "/fraud/alerts", "fraud_analyst", query={"limit": "1", "offset": "1"}).body
        self.assertEqual((len(page["items"]), page["limit"], page["offset"]), (1, 1, 1))
        high = api.call("GET", "/fraud/alerts", "fraud_analyst", query={"band": "high"}).body
        self.assertTrue(all(i["band"] == "high" for i in high["items"]))

    def test_summary_has_no_identifiers(self):
        api = Api()
        body = api.call("GET", "/fraud/summary", "viewer").body
        self.assertEqual(set(body), {"alerts_total", "alerts_by_band", "last_window_start", "cases_by_status"})

    def test_missing_alert_is_404(self):
        self.assertEqual(Api().call("GET", "/fraud/alerts/99999", "fraud_analyst").status, 404)


class ValidationTests(unittest.TestCase):
    CASES = [
        ("GET", "/fraud/alerts", {"limit": "0"}, None),
        ("GET", "/fraud/alerts", {"limit": "201"}, None),
        ("GET", "/fraud/alerts", {"limit": "abc"}, None),
        ("GET", "/fraud/alerts", {"offset": "-1"}, None),
        ("GET", "/fraud/alerts", {"band": "extreme"}, None),
        ("GET", "/fraud/alerts", {"network": "x'; DROP TABLE fraud_alerts;--"}, None),
        ("GET", "/fraud/alerts", {"surprise": "1"}, None),
        ("GET", "/fraud/alerts/abc", None, None),
        ("GET", "/fraud/alerts/1", {"unmask": "maybe"}, None),
        ("POST", "/fraud/cases", None, {"alert_ids": []}),
        ("POST", "/fraud/cases", None, {"alert_ids": [1, 1]}),
        ("POST", "/fraud/cases", None, {"alert_ids": ["1"]}),
        ("POST", "/fraud/cases", None, {"alert_ids": [True]}),
        ("POST", "/fraud/cases", None, {"alert_ids": list(range(1, 52))}),
        ("POST", "/fraud/cases", None, {"alert_ids": [1], "priority": "P9"}),
        ("POST", "/fraud/cases", None, {"alert_ids": [1], "extra": "x"}),
        ("POST", "/fraud/cases", None, [1, 2]),
        ("POST", "/fraud/cases/1/transition", None, {"to_status": "Nonsense"}),
        ("POST", "/fraud/cases/1/transition", None, {"to_status": "Triaged", "reason": "x" * 501}),
        ("POST", "/fraud/cases/1/reopen", None, {"reason": "short"}),
        ("POST", "/fraud/cases/1/notes", None, {"body": ""}),
        ("POST", "/fraud/cases/1/notes", None, {"body": "x" * 2001}),
        ("PUT", "/fraud/rules/repeated_destination", None, {"params": {"threshold": -5}, "weight": 0.5}),
        ("PUT", "/fraud/rules/repeated_destination", None, {"params": {"threshold": 5}, "weight": 1.5}),
        ("PUT", "/fraud/rules/repeated_destination", None, {"params": {"threshold": 5}, "weight": float("nan")}),
        ("PUT", "/fraud/rules/repeated_destination", None, {"params": {"evil": 5}, "weight": 0.5}),
        ("PUT", "/fraud/rules/repeated_destination", None, {"params": {"threshold": "5"}, "weight": 0.5}),
        ("PUT", "/fraud/rules/Bad-Key", None, {"params": {"threshold": 5}, "weight": 0.5}),
        ("POST", "/fraud/ingest", None, {"file_name": "../../etc/passwd", "content": "x"}),
        ("POST", "/fraud/ingest", None, {"file_name": "a/b.csv", "content": "x"}),
        ("POST", "/fraud/ingest", None, {"file_name": "a.exe", "content": "x"}),
        ("POST", "/fraud/ingest", None, {"file_name": "a.csv", "content": ""}),
    ]

    def test_bad_input_is_422_and_changes_nothing(self):
        api = Api()
        api.new_case()
        before = api.snapshot()
        for method, path, query, body in self.CASES:
            resp = api.call(method, path, "fraud_analyst", query=query, body=body)
            self.assertEqual(resp.status, 422, f"{method} {path} {query} {body}: {resp.body}")
        self.assertEqual(api.snapshot(), before)

    def test_validation_runs_after_authorization(self):
        api = Api()
        self.assertEqual(api.call("POST", "/fraud/cases", "viewer", body={"alert_ids": []}).status, 403)


class RuleEditTests(unittest.TestCase):
    def test_edit_creates_new_version_keeps_old_and_audits_old_and_new(self):
        api = Api()
        r = api.call("PUT", "/fraud/rules/repeated_destination", "fraud_analyst",
                     body={"params": {"threshold": 40}, "weight": 0.7, "enabled": True})
        self.assertEqual((r.status, r.body["version"]), (200, 2))
        self.assertEqual(len([x for x in api.repo.rules if x["rule_key"] == "repeated_destination"]), 2)
        listed = {x["rule_key"]: x for x in api.call("GET", "/fraud/rules", "administrator").body["items"]}
        self.assertEqual(listed["repeated_destination"]["params"], {"threshold": 40})
        d = api.repo.audit[-1]["details"]
        self.assertEqual((d["from_version"], d["to_version"], d["old"]["params"], d["new"]["params"]),
                         (1, 2, {"threshold": 25}, {"threshold": 40}))

    def test_unknown_rule_404_and_missing_param_422(self):
        api = Api()
        ok = {"params": {"threshold": 5}, "weight": 0.5}
        self.assertEqual(api.call("PUT", "/fraud/rules/nope", "fraud_analyst", body=ok).status, 404)
        r = api.call("PUT", "/fraud/rules/spiking_sender", "fraud_analyst", body=ok)
        self.assertEqual(r.status, 422)  # spiking_sender needs all five params


class IngestEndpointTests(unittest.TestCase):
    def test_ingest_then_duplicate_is_skipped(self):
        api = Api()
        body = {"file_name": "a.csv", "content": _csv()}
        first = api.call("POST", "/fraud/ingest", "fraud_analyst", body=body)
        again = api.call("POST", "/fraud/ingest", "fraud_analyst", body={**body, "file_name": "b.csv"})
        self.assertEqual((first.status, first.body["status"], first.body["rows_loaded"]), (200, "loaded", 50))
        self.assertEqual(again.body["status"], "skipped_duplicate_file")
        self.assertEqual(len(api.store.records), 50)
        self.assertEqual([r["action"] for r in api.repo.audit[-2:]], ["ingest.upload"] * 2)

    def test_schema_error_is_422_and_audited_as_failure(self):
        api = Api()
        r = api.call("POST", "/fraud/ingest", "fraud_analyst", body={"file_name": "a.csv", "content": "a,b\n1,2\n"})
        self.assertEqual((r.status, r.body["error"]), (422, "invalid_schema"))
        self.assertEqual(api.repo.audit[-1]["outcome"], "failure")

    def test_oversize_is_413(self):
        api = Api()
        big = "x" * 250_000
        self.assertEqual(api.call("POST", "/fraud/ingest", "fraud_analyst", body={"file_name": "a.csv", "content": big}).status, 413)


class AuditChainTests(unittest.TestCase):
    def _api_with_history(self):
        api = Api()
        api.call("PUT", "/fraud/rules/repeated_destination", "fraud_analyst",
                 body={"params": {"threshold": 40}, "weight": 0.7, "enabled": True})
        api.new_case()
        api.call("GET", "/fraud/alerts", "viewer")  # a denial row
        return api

    def test_untouched_chain_verifies(self):
        api = self._api_with_history()
        r = api.call("GET", "/audit/verify", "security_analyst").body
        self.assertTrue(r["ok"])
        self.assertGreaterEqual(r["rows"], 3)

    def test_edited_row_is_detected(self):
        api = self._api_with_history()
        api.repo.audit[1]["details"] = {"forged": True}
        r = api.call("GET", "/audit/verify", "administrator").body
        self.assertEqual((r["ok"], r["first_bad_audit_id"], r["reason"]), (False, api.repo.audit[1]["audit_id"], "hash_mismatch"))

    def test_deleted_middle_row_is_detected(self):
        api = self._api_with_history()
        del api.repo.audit[1]
        r = audit.verify_chain(api.repo.iter_audit())
        self.assertEqual((r.ok, r.reason), (False, "broken_link"))

    def test_reordered_rows_are_detected(self):
        api = self._api_with_history()
        api.repo.audit[0], api.repo.audit[1] = api.repo.audit[1], api.repo.audit[0]
        self.assertFalse(audit.verify_chain(api.repo.iter_audit()).ok)

    def test_known_limit_tail_truncation_is_not_detected(self):
        api = self._api_with_history()
        api.repo.audit.pop()
        self.assertTrue(audit.verify_chain(api.repo.iter_audit()).ok)  # documented limitation

    def test_audit_listing_newest_first(self):
        api = self._api_with_history()
        items = api.call("GET", "/audit", "administrator").body["items"]
        self.assertGreater(items[0]["audit_id"], items[-1]["audit_id"])


if __name__ == "__main__":
    unittest.main()
