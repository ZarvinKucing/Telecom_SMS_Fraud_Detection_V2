"""Detection worker: read records for a window, run rules (+ anomaly signal), persist alerts.

`source` needs fetch_records(start, end); `sink` needs save_detection(rules, alerts, components).
PostgresStore provides both; tests use InMemoryStore as source and MemoryRepo as sink.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any

from fraud_engine.anomaly import AnomalyConfig, as_rule_record
from fraud_engine.pipeline import run_detection
from fraud_engine.rule_registry import load_rules, seed_default_rules

log = logging.getLogger(__name__)


def run_cycle(source: Any, sink: Any, rule_repo: Any, start: datetime, end: datetime,
              network_scope: tuple[str, ...] = (), anomaly: AnomalyConfig | None = None) -> int:
    seed_default_rules(rule_repo)
    rules = load_rules(rule_repo)
    records = source.fetch_records(start, end)
    result = run_detection(records, rules, network_scope=network_scope, anomaly=anomaly)
    persisted = [*rules, as_rule_record(anomaly)] if anomaly is not None else rules
    sink.save_detection(persisted, result.alerts, result.components)
    log.info("detection cycle", extra={"records": len(records), "alerts": len(result.alerts)})
    return len(result.alerts)


def main() -> None:  # pragma: no cover - long-running loop; run_cycle is covered by isolated PostgreSQL smoke tests
    import os
    from datetime import UTC, timedelta

    from backend.db_roles import verify_runtime_role
    from backend.sql_repo import SqlRepo
    from common.config import Settings
    from common.logging import configure_logging
    from fraud_engine.pg_store import PostgresStore, make_engine

    settings = Settings.from_env()
    configure_logging(settings.log_level)
    engine = make_engine(settings.require_database_url())
    try:
        verify_runtime_role(engine)
    except Exception:
        engine.dispose()
        raise
    store, repo = PostgresStore(engine), SqlRepo(engine)
    interval = int(os.environ.get("WORKER_INTERVAL_SECONDS", "300"))
    lookback = timedelta(days=int(os.environ.get("WORKER_LOOKBACK_DAYS", "8")))
    try:
        while True:
            try:
                now = datetime.now(UTC)
                run_cycle(store, repo, repo, now - lookback, now, settings.network_scope, AnomalyConfig())
            except Exception:
                log.exception("detection cycle failed")
            time.sleep(interval)
    except KeyboardInterrupt:
        log.info("detection worker stopping")
    finally:
        engine.dispose()


if __name__ == "__main__":  # pragma: no cover
    main()
