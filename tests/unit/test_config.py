import re
import unittest
from pathlib import Path

from common.config import ConfigError, Settings

ROOT = Path(__file__).resolve().parents[2]


class ConfigTests(unittest.TestCase):
    def test_database_url_required_and_has_no_default(self):
        s = Settings.from_env({})
        self.assertIsNone(s.database_url)
        with self.assertRaises(ConfigError):
            s.require_database_url()

    def test_network_scope_parsed(self):
        self.assertEqual(Settings.from_env({"NETWORK_SCOPE": " NET_A, NET_B ,"}).network_scope, ("NET_A", "NET_B"))

    def test_api_settings_have_safe_defaults_and_parse_values(self):
        defaults = Settings.from_env({})
        self.assertIsNone(defaults.jwt_issuer)
        self.assertIsNone(defaults.jwt_public_key_pem)
        self.assertEqual((defaults.jwt_audience, defaults.max_ingest_bytes), ("fraud-api", 5_000_000))
        configured = Settings.from_env({"JWT_ISSUER": "issuer", "JWT_AUDIENCE": "api",
                                        "JWT_PUBLIC_KEY_PEM": "pem", "MAX_INGEST_BYTES": "1234"})
        self.assertEqual((configured.jwt_issuer, configured.jwt_audience, configured.jwt_public_key_pem,
                          configured.max_ingest_bytes), ("issuer", "api", "pem", 1234))

    def test_invalid_runtime_limits_and_timezone_fail_closed(self):
        for env in ({"MAX_INGEST_BYTES": "0"}, {"MAX_INGEST_BYTES": "not-an-int"},
                    {"SOURCE_TIMEZONE": "Not/A_Timezone"}, {"JWT_AUDIENCE": "  "}):
            with self.subTest(env=env), self.assertRaises(ConfigError):
                Settings.from_env(env)

    def test_openapi_is_disabled_by_default_and_public_only_in_development_or_test(self):
        defaults = Settings.from_env({})
        self.assertEqual((defaults.app_environment, defaults.openapi_public), ("production", False))
        for environment in ("development", "test", "staging", "production"):
            with self.subTest(environment=environment):
                self.assertFalse(Settings.from_env({"APP_ENV": environment}).openapi_public)
        self.assertTrue(Settings.from_env({"APP_ENV": "development", "OPENAPI_PUBLIC": "true"}).openapi_public)
        self.assertTrue(Settings.from_env({"APP_ENV": "test", "OPENAPI_PUBLIC": "true"}).openapi_public)
        for env in ({"APP_ENV": "production", "OPENAPI_PUBLIC": "true"},
                    {"APP_ENV": "staging", "OPENAPI_PUBLIC": "true"},
                    {"OPENAPI_PUBLIC": "perhaps"}):
            with self.subTest(env=env), self.assertRaises(ConfigError):
                Settings.from_env(env)

    def test_env_example_ships_no_credentials(self):
        for line in (ROOT / ".env.example").read_text().splitlines():
            if line.startswith(("POSTGRES_PASSWORD=", "DATABASE_URL=", "POSTGRES_USER=")):
                self.assertEqual(line.split("=", 1)[1].strip(), "", line)

    def test_no_hardcoded_secret_patterns_in_source(self):
        pattern = re.compile(r"(password|passwd|secret|api[_-]?key)\s*=\s*[\"'][^\"']+[\"']", re.I)
        for py in [*ROOT.glob("common/**/*.py"), *ROOT.glob("fraud_engine/**/*.py"), *ROOT.glob("synthetic_data/*.py")]:
            self.assertIsNone(pattern.search(py.read_text()), py)

    def test_no_string_formatted_sql_in_source(self):
        bad = re.compile(r"(execute|read_sql)\(\s*f[\"']", re.I)
        for py in ROOT.glob("fraud_engine/**/*.py"):
            self.assertIsNone(bad.search(py.read_text()), py)


if __name__ == "__main__":
    unittest.main()
