"""Process entry point:  uvicorn backend.main:create --factory --host 127.0.0.1 --port 8000

Fails closed: refuses to start without a database URL and token-verification settings.
"""
from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from backend.app import create_app
from backend.auth.tokens import verify_token
from backend.core import AppContext
from backend.db_roles import verify_runtime_role
from backend.sql_repo import SqlRepo
from common.config import ConfigError, Settings
from common.logging import configure_logging
from fraud_engine.pg_store import PostgresStore, make_engine
from fraud_engine.rule_registry import seed_default_rules


def create() -> Any:
    s = Settings.from_env()
    configure_logging(s.log_level)
    if not (s.jwt_issuer and s.jwt_public_key_pem and s.jwt_audience):
        raise ConfigError("JWT_ISSUER and JWT_PUBLIC_KEY_PEM must be set; the API will not start unauthenticated")
    pem = s.jwt_public_key_pem.replace("\\n", "\n").encode()
    try:
        public_key = serialization.load_pem_public_key(pem)
    except (TypeError, ValueError) as exc:
        raise ConfigError("JWT_PUBLIC_KEY_PEM must contain a valid RSA public key") from exc
    if not isinstance(public_key, RSAPublicKey) or public_key.key_size < 2048:
        raise ConfigError("JWT_PUBLIC_KEY_PEM must contain an RSA public key of at least 2048 bits")
    issuer, audience = s.jwt_issuer, s.jwt_audience
    engine = make_engine(s.require_database_url())
    try:
        verify_runtime_role(engine)
        repo = SqlRepo(engine)
        seed_default_rules(repo)
        ctx = AppContext(repo=repo, store=PostgresStore(engine, repo.current_connection),
                         source_tz=s.source_timezone, max_ingest_bytes=s.max_ingest_bytes,
                         verify=lambda token: verify_token(token, lambda _t: pem, issuer, audience))
        app = create_app(ctx, on_shutdown=engine.dispose, openapi_public=s.openapi_public)
        return app
    except Exception:
        engine.dispose()
        raise
