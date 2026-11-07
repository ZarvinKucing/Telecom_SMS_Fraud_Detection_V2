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
