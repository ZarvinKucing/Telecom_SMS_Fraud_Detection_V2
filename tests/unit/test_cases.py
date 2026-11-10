import unittest

from backend.services.cases import STATUSES, TRANSITIONS
from tests.unit.api_fixtures import Api

F = "fraud_analyst"


def post(api, case_id, to, sub="alice", reason=None):
    body = {"to_status": to} | ({"reason": reason} if reason else {})
    return api.call("POST", f"/fraud/cases/{case_id}/transition", F, body=body, sub=sub)


class WorkflowTests(unittest.TestCase):
    def test_transition_table_is_closed_and_complete(self):
        self.assertEqual(set(TRANSITIONS), set(STATUSES))
        for dests in TRANSITIONS.values():
            self.assertTrue(set(dests) <= set(STATUSES))
        self.assertEqual(TRANSITIONS["Closed"], ())

    def test_create_case_links_alerts_sets_priority_and_logs_event(self):
        api = Api()
        ids = api.alert_ids()[:2]
        r = api.call("POST", "/fraud/cases", F, body={"alert_ids": ids}, sub="alice")
        self.assertEqual(r.status, 201)
        c = r.body
        self.assertEqual((c["status"], c["opened_by_sub"], c["alert_ids"], c["priority"]), ("New", "alice", sorted(ids), "P2"))
        self.assertEqual([(e["from_status"], e["to_status"]) for e in c["events"]], [(None, "New")])
        self.assertEqual(api.repo.audit[-1]["action"], "case.create")

    def test_explicit_priority_wins(self):
        api = Api()
        r = api.call("POST", "/fraud/cases", F, body={"alert_ids": api.alert_ids()[:1], "priority": "P4"})
        self.assertEqual(r.body["priority"], "P4")

    def test_alert_cannot_join_two_cases_and_missing_alert_is_404(self):
        api = Api()
        aid = api.alert_ids()[0]
        self.assertEqual(api.call("POST", "/fraud/cases", F, body={"alert_ids": [aid]}).status, 201)
        self.assertEqual(api.call("POST", "/fraud/cases", F, body={"alert_ids": [aid]}).status, 409)
        self.assertEqual(api.call("POST", "/fraud/cases", F, body={"alert_ids": [99999]}).status, 404)

    def test_failed_create_does_not_link_any_alert(self):
        api = Api()
        a, b = api.alert_ids()[:2]
        api.call("POST", "/fraud/cases", F, body={"alert_ids": [b]})
        self.assertEqual(api.call("POST", "/fraud/cases", F, body={"alert_ids": [a, b]}).status, 409)
        self.assertIsNone(api.repo.alerts[a]["case_id"])

    def test_full_happy_path_confirmed_fraud(self):
        api = Api()
        cid = api.new_case()
        for to in ("Triaged", "Investigating", "ConfirmedFraud", "Closed"):
            self.assertEqual(post(api, cid, to).status, 200, to)
        c = api.call("GET", f"/fraud/cases/{cid}", F).body
        self.assertEqual((c["status"], c["outcome_label"], c["assignee_sub"]), ("Closed", "confirmed_fraud", "alice"))
        self.assertIsNotNone(c["closed_at"])
        self.assertEqual([e["to_status"] for e in c["events"]], ["New", "Triaged", "Investigating", "ConfirmedFraud", "Closed"])

    def test_false_positive_label_and_needs_info_loop(self):
        api = Api()
        cid = api.new_case()
        for to in ("Triaged", "Investigating", "NeedsInfo", "Investigating", "FalsePositive", "Closed"):
            self.assertEqual(post(api, cid, to).status, 200, to)
        self.assertEqual(api.repo.cases[cid]["outcome_label"], "false_positive")

    def test_every_illegal_transition_is_409_and_changes_nothing(self):
        for src in STATUSES:
            for dst in STATUSES:
                if dst in TRANSITIONS[src]:
                    continue
                api = Api()
                cid = api.new_case()
                path = {"New": [], "Triaged": ["Triaged"], "Investigating": ["Triaged", "Investigating"],
                        "NeedsInfo": ["Triaged", "Investigating", "NeedsInfo"],
                        "ConfirmedFraud": ["Triaged", "Investigating", "ConfirmedFraud"],
                        "FalsePositive": ["Triaged", "Investigating", "FalsePositive"],
                        "Closed": ["Triaged", "Investigating", "FalsePositive", "Closed"]}[src]
                for step in path:
                    self.assertEqual(post(api, cid, step).status, 200)
                events, audits = len(api.repo.events), len(api.repo.audit)
                self.assertEqual(post(api, cid, dst).status, 409, f"{src}->{dst}")
                self.assertEqual((api.repo.cases[cid]["status"], len(api.repo.events), len(api.repo.audit)),
                                 (src, events, audits))

    def test_closed_case_cannot_be_reopened_by_ordinary_transition(self):
        api = Api()
        cid = api.new_case()
        for to in ("Triaged", "Investigating", "FalsePositive", "Closed"):
            post(api, cid, to)
        self.assertEqual(post(api, cid, "Investigating").status, 409)

    def test_reopen_needs_reason_is_audited_and_clears_outcome(self):
        api = Api()
        cid = api.new_case()
        for to in ("Triaged", "Investigating", "ConfirmedFraud", "Closed"):
            post(api, cid, to)
        url = f"/fraud/cases/{cid}/reopen"
        self.assertEqual(api.call("POST", url, F, body={"reason": "short"}).status, 422)
        r = api.call("POST", url, F, body={"reason": "new evidence from carrier"}, sub="bob")
        self.assertEqual((r.status, r.body["status"], r.body["outcome_label"], r.body["assignee_sub"]),
                         (200, "Investigating", None, "bob"))
        self.assertEqual(api.repo.audit[-1]["details"], {"previous_outcome": "confirmed_fraud"})
        self.assertEqual(api.call("POST", url, F, body={"reason": "reopen an open case"}).status, 409)

    def test_assignee_taken_on_first_investigation_only(self):
        api = Api()
        cid = api.new_case()
        post(api, cid, "Triaged", sub="alice")
        post(api, cid, "Investigating", sub="alice")
        post(api, cid, "NeedsInfo", sub="bob")
        post(api, cid, "Investigating", sub="bob")
        self.assertEqual(api.repo.cases[cid]["assignee_sub"], "alice")

    def test_notes_are_audited_without_storing_the_body_in_audit(self):
        api = Api()
        cid = api.new_case()
        r = api.call("POST", f"/fraud/cases/{cid}/notes", F, body={"body": "sensitive analyst remark"}, sub="alice")
        self.assertEqual((r.status, r.body["author_sub"]), (201, "alice"))
        self.assertNotIn("sensitive", str(api.repo.audit[-1]))
        self.assertEqual(api.repo.audit[-1]["details"]["length"], len("sensitive analyst remark"))

    def test_unknown_case_is_404(self):
        api = Api()
        self.assertEqual(api.call("GET", "/fraud/cases/999", F).status, 404)
        self.assertEqual(post(api, 999, "Triaged").status, 404)

    def test_list_cases_filters_by_status(self):
        api = Api()
        a, b = api.new_case(skip=0), api.new_case(skip=1)
        post(api, a, "Triaged")
        got = api.call("GET", "/fraud/cases", F, query={"status": "Triaged"}).body
        self.assertEqual([c["case_id"] for c in got["items"]], [a])
        self.assertEqual(api.call("GET", "/fraud/cases", F).body["total"], 2)
        self.assertNotEqual(a, b)


class AtomicityTests(unittest.TestCase):
    def test_failing_audit_write_rolls_back_the_case_change_and_event(self):
        api = Api()
        cid = api.new_case()
        original = api.repo.append_audit

        def boom(fields):
            if fields["action"] == "case.transition":
                raise RuntimeError("audit store unavailable")
            return original(fields)

        api.repo.append_audit = boom
        events, audits = len(api.repo.events), len(api.repo.audit)
        r = post(api, cid, "Triaged")
        self.assertEqual(r.status, 500)
        self.assertEqual((api.repo.cases[cid]["status"], len(api.repo.events), len(api.repo.audit)),
                         ("New", events, audits))

    def test_failing_audit_on_create_leaves_alerts_unlinked(self):
        api = Api()
        original = api.repo.append_audit
        api.repo.append_audit = lambda f: (_ for _ in ()).throw(RuntimeError("x")) if f["action"] == "case.create" else original(f)
        aid = api.alert_ids()[0]
        self.assertEqual(api.call("POST", "/fraud/cases", F, body={"alert_ids": [aid]}).status, 500)
        self.assertEqual((api.repo.alerts[aid]["case_id"], len(api.repo.cases)), (None, 0))


if __name__ == "__main__":
    unittest.main()
