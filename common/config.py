"""Settings read from environment variables. No credential has a default."""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dotenv import load_dotenv


class ConfigError(RuntimeError):
    """Raised when required configuration is missing."""


def _split(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


@dataclass(frozen=True)
class Settings:
    database_url: str | None = None
    source_timezone: str = "UTC"
    network_scope: tuple[str, ...] = ()
    input_dir: str = "./data/incoming"
    processed_dir: str = "./data/processed"
    output_dir: str = "./out"
    log_level: str = "INFO"
    jwt_issuer: str | None = None
    jwt_audience: str = "fraud-api"
    jwt_public_key_pem: str | None = None
    max_ingest_bytes: int = 5_000_000
    app_environment: str = "production"
    openapi_public: bool = False

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        if env is None:
            load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)
            e = os.environ
        else:
            e = env
        try:
            max_ingest_bytes = int(e.get("MAX_INGEST_BYTES", "5000000"))
        except (TypeError, ValueError) as exc:
            raise ConfigError("MAX_INGEST_BYTES must be a positive integer") from exc
        if max_ingest_bytes <= 0:
            raise ConfigError("MAX_INGEST_BYTES must be a positive integer")
        source_timezone = e.get("SOURCE_TIMEZONE", "UTC")
        try:
            ZoneInfo(source_timezone)
        except (TypeError, ValueError, ZoneInfoNotFoundError) as exc:
            raise ConfigError("SOURCE_TIMEZONE must be a valid IANA time zone") from exc
        audience = (e.get("JWT_AUDIENCE", "fraud-api") or "").strip()
        if not audience:
            raise ConfigError("JWT_AUDIENCE must not be empty")
        app_environment = (e.get("APP_ENV", "production") or "").strip().lower()
        if app_environment not in {"development", "test", "staging", "production"}:
            raise ConfigError("APP_ENV must be development, test, staging, or production")
        openapi_value = (e.get("OPENAPI_PUBLIC", "false") or "").strip().lower()
        if openapi_value not in {"true", "false"}:
            raise ConfigError("OPENAPI_PUBLIC must be true or false")
        openapi_public = openapi_value == "true"
        if openapi_public and app_environment not in {"development", "test"}:
            raise ConfigError("OPENAPI_PUBLIC=true is allowed only in development or test")
        return cls(
            database_url=e.get("DATABASE_URL") or None,
            source_timezone=source_timezone,
            network_scope=_split(e.get("NETWORK_SCOPE", "")),
            input_dir=e.get("INPUT_DIR", "./data/incoming"),
            processed_dir=e.get("PROCESSED_DIR", "./data/processed"),
            output_dir=e.get("OUTPUT_DIR", "./out"),
            log_level=e.get("LOG_LEVEL", "INFO").upper(),
            jwt_issuer=(e.get("JWT_ISSUER") or "").strip() or None,
            jwt_audience=audience,
            jwt_public_key_pem=e.get("JWT_PUBLIC_KEY_PEM") or None,
            max_ingest_bytes=max_ingest_bytes,
            app_environment=app_environment,
            openapi_public=openapi_public,
        )

    def require_database_url(self) -> str:
        if not self.database_url:
            raise ConfigError("DATABASE_URL is not set; copy .env.example to .env and fill it in")
        return self.database_url
