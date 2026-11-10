from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from common.config import ConfigError


class MainFactoryConfigurationTests(unittest.TestCase):
    def test_main_factory_fails_before_database_connect_without_jwt_settings(self):
        with patch.dict(os.environ, {"PYTHON_DOTENV_DISABLED": "1", "DATABASE_URL": "unused"}, clear=True):
            with patch("backend.main.make_engine") as make_engine:
                from backend.main import create

                with self.assertRaises(ConfigError):
                    create()
                make_engine.assert_not_called()

    def test_invalid_jwt_public_key_fails_before_database_connect(self):
        with patch.dict(os.environ, {"PYTHON_DOTENV_DISABLED": "1", "DATABASE_URL": "unused",
                                     "JWT_ISSUER": "issuer", "JWT_AUDIENCE": "audience",
                                     "JWT_PUBLIC_KEY_PEM": "not-a-key"}, clear=True):
            with patch("backend.main.make_engine") as make_engine:
                from backend.main import create

                with self.assertRaisesRegex(ConfigError, "valid RSA public key"):
                    create()
                make_engine.assert_not_called()
