import re
import sys
import unittest
from pathlib import Path

from backend.core import Router
from backend.handlers import router
from backend.openapi import build_spec

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import check_routes  # noqa: E402


class RouteCheckTests(unittest.TestCase):
    def test_real_router_passes(self):
        self.assertEqual(check_routes.check(router), [])

    def test_route_without_permission_fails(self):
        bad = Router()
        bad.add("GET", "/oops", None)(lambda *a: (200, {}))
        self.assertEqual(check_routes.main([], bad), 1)

    def test_unknown_permission_fails(self):
        bad = Router()
        bad.add("GET", "/oops", "made:up:permission")(lambda *a: (200, {}))
        self.assertTrue(check_routes.check(bad))

    def test_public_state_changing_route_fails(self):
        bad = Router()
        bad.add("POST", "/oops", "public", writes=True)(lambda *a: (200, {}))
        self.assertTrue(check_routes.check(bad))

    def test_docs_api_table_is_current(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            check_routes.main(["--markdown"])
        doc = (ROOT / "docs" / "api.md").read_text()
        self.assertIn(buf.getvalue().strip(), doc, "regenerate: python scripts/check_routes.py --markdown")


class OpenApiTests(unittest.TestCase):
    def test_app_mounts_schema_only_when_explicitly_enabled(self):
        from backend.app import create_app
        from tests.unit.api_fixtures import Api

        ctx = Api(seed_alerts=False).ctx
        disabled_paths = {route.path for route in create_app(ctx).routes}
        enabled_paths = {route.path for route in create_app(ctx, openapi_public=True).routes}
        self.assertNotIn("/openapi.json", disabled_paths)
        self.assertIn("/openapi.json", enabled_paths)

    def test_every_route_is_documented_with_its_permission(self):
        spec = build_spec(router, openapi_public=True)
        for r in router.routes:
            op = spec["paths"][r.pattern][r.method.lower()]
            self.assertEqual(op["x-required-permission"], r.permission)
            self.assertEqual("security" in op, r.permission != "public")

    def test_schema_documents_route_statuses_and_public_schema_policy(self):
        paths = build_spec(router, openapi_public=True)["paths"]
        self.assertIn("/openapi.json", paths)
        self.assertEqual(paths["/openapi.json"]["get"]["x-required-permission"], "public_development_only")
        self.assertTrue({"201", "400", "401", "403", "404", "405", "413", "422", "500"}
                        <= set(paths["/fraud/cases"]["post"]["responses"]))
        self.assertIn("502", paths["/fraud/ingest"]["post"]["responses"])
        self.assertIn("409", paths["/fraud/cases/{case_id}/transition"]["post"]["responses"])

    def test_schema_endpoint_is_absent_when_disabled(self):
        self.assertNotIn("/openapi.json", build_spec(router)["paths"])


class SqlSafetyTests(unittest.TestCase):
    ALLOWED_INTERPOLATIONS = {"where", "_ALERT_COLS", "self._AUDIT_COLS"}

    def test_sql_f_strings_only_interpolate_known_constants(self):
        for py in [*ROOT.glob("backend/**/*.py"), *ROOT.glob("fraud_engine/**/*.py")]:
            for n, line in enumerate(py.read_text().splitlines(), 1):
                if re.search(r'\bf"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|FROM)\b', line):
                    self.assertIn("noqa: S608", line, f"{py.name}:{n} f-string SQL needs review")
                    names = set(re.findall(r"\{([^}]+)\}", re.search(r'f"[^"]*"', line).group(0)))
                    self.assertTrue(names <= self.ALLOWED_INTERPOLATIONS, f"{py.name}:{n} interpolates {names}")

    def test_user_values_are_always_bound_parameters(self):
        src = (ROOT / "backend" / "sql_repo.py").read_text()
        self.assertNotIn("% ", re.sub(r"#.*", "", "".join(re.findall(r'text\([^)]*\)', src))))
        self.assertNotIn(".format(", src)


if __name__ == "__main__":
    unittest.main()
