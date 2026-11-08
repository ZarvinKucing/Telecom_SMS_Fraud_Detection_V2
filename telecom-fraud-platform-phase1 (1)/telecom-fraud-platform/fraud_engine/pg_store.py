"""PostgreSQL implementation of RecordStore plus detection persistence.

STATUS: written but NOT executed in the authoring environment (no PostgreSQL, no network to install
SQLAlchemy). Treat as unverified until run against a real database. Staging-table COPY, mentioned
in the blueprint, is deferred: this uses chunked multi-row INSERT ... ON CONFLICT DO NOTHING.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

import pandas as pd
from sqlalchemy import Engine, create_engine, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from common.db.models import (FraudAlert, FraudRuleRow, IngestBatch, RejectedRow, RiskScoreComponent,
                              SmsRecord)
from fraud_engine.ingest import BatchInfo, LoadResult
from fraud_engine.rules import FraudRule

CHUNK = 1000


def make_engine(database_url: str) -> Engine:
    return create_engine(database_url, pool_pre_ping=True)


def _records(df: pd.DataFrame, batch_id: str) -> list[dict[str, object]]:
    out = []
    for r in df.to_dict("records"):
        r["received_time"] = pd.Timestamp(r["received_time"]).to_pydatetime()
        r["batch_id"] = batch_id
        out.append(r)
    return out


class PostgresStore:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def batch_exists(self, file_sha256: str) -> bool:
        with self.engine.connect() as conn:
            row = conn.execute(select(IngestBatch.batch_id).where(IngestBatch.file_sha256 == file_sha256))
            return row.first() is not None

    def load_batch(self, batch: BatchInfo, records: pd.DataFrame, rejected: pd.DataFrame) -> LoadResult:
        loaded = 0
        with self.engine.begin() as conn:  # single transaction: rolls back on any exception
            conn.execute(pg_insert(IngestBatch).values(
                batch_id=batch.batch_id, file_name=batch.file_name, file_sha256=batch.file_sha256,
                rows_read=batch.rows_read))
            rows = _records(records, batch.batch_id)
            for i in range(0, len(rows), CHUNK):
                stmt = pg_insert(SmsRecord).values(rows[i:i + CHUNK]).on_conflict_do_nothing(
                    index_elements=["message_id", "received_time"])
                loaded += conn.execute(stmt).rowcount
            if len(rejected):
                conn.execute(pg_insert(RejectedRow), [
                    {"batch_id": batch.batch_id, "line_number": int(r.line_number), "reason": r.reason}
                    for r in rejected.itertuples()])
            conn.execute(update(IngestBatch).where(IngestBatch.batch_id == batch.batch_id).values(
                rows_loaded=loaded, rows_rejected=len(rejected), finished_at=datetime.now(UTC)))
        return LoadResult(rows_loaded=loaded)

    def fetch_records(self, start: datetime, end: datetime) -> pd.DataFrame:
        """Records with start <= received_time < end (parameterized)."""
        query = text("""SELECT message_id, received_time, source_addr, destination_addr, network
                        FROM sms_records WHERE received_time >= :start AND received_time < :end""")
        with self.engine.connect() as conn:
            return pd.read_sql(query, conn, params={"start": start, "end": end})

    def save_detection(self, rules: Sequence[FraudRule], alerts: pd.DataFrame, components: pd.DataFrame) -> None:
        """Upsert alerts (idempotent per window/entity/network) and replace their components."""
        keys = ["window_start", "entity_type", "entity_key", "network"]
        with self.engine.begin() as conn:
            rule_pk: dict[tuple[str, int], int] = {}
            for r in rules:
                conn.execute(pg_insert(FraudRuleRow).values(
                    rule_key=r.rule_key, version=r.version, rule_type=r.rule_type, params=r.params,
                    weight=r.weight, enabled=r.enabled).on_conflict_do_nothing(
                        index_elements=["rule_key", "version"]))
                pk = conn.execute(select(FraudRuleRow.rule_pk).where(
                    FraudRuleRow.rule_key == r.rule_key, FraudRuleRow.version == r.version)).scalar_one()
                rule_pk[(r.rule_key, r.version)] = pk
            for a in alerts.to_dict("records"):
                ws = pd.Timestamp(a["window_start"]).to_pydatetime()
                stmt = pg_insert(FraudAlert).values(
                    window_start=ws, entity_type=a["entity_type"], entity_key=a["entity_key"],
                    network=a["network"], risk_score=a["risk_score"], band=a["band"])
                stmt = stmt.on_conflict_do_update(
                    constraint="uq_alert_window_entity",
                    set_={"risk_score": stmt.excluded.risk_score, "band": stmt.excluded.band})
                alert_id = conn.execute(stmt.returning(FraudAlert.alert_id)).scalar_one()
                conn.execute(text("DELETE FROM risk_score_components WHERE alert_id = :id"), {"id": alert_id})
                mask = (components[keys] == pd.Series({k: a[k] for k in keys})).all(axis=1)
                for c in components[mask].to_dict("records"):
                    conn.execute(pg_insert(RiskScoreComponent).values(
                        alert_id=alert_id, rule_pk=rule_pk[(c["rule_key"], int(c["rule_version"]))],
                        severity=c["severity"], evidence=c["evidence"]))
