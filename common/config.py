"""Settings read from environment variables. No credential has a default."""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass


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

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env
        return cls(
            database_url=e.get("DATABASE_URL") or None,
            source_timezone=e.get("SOURCE_TIMEZONE", "UTC"),
            network_scope=_split(e.get("NETWORK_SCOPE", "")),
            input_dir=e.get("INPUT_DIR", "./data/incoming"),
            processed_dir=e.get("PROCESSED_DIR", "./data/processed"),
            output_dir=e.get("OUTPUT_DIR", "./out"),
            log_level=e.get("LOG_LEVEL", "INFO").upper(),
        )

    def require_database_url(self) -> str:
        if not self.database_url:
            raise ConfigError("DATABASE_URL is not set; copy .env.example to .env and fill it in")
        return self.database_url
