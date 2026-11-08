"""SQLAlchemy 2.0 models for the Phase 1 schema.

STATUS: written but NOT executed in the authoring environment (no network, no
PostgreSQL, SQLAlchemy not installable there). Verify with `alembic upgrade head`.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, Numeric, Text,
                        UniqueConstraint, func)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class IngestBatch(Base):
    __tablename__ = "ingest_batches"
    batch_id: Mapped[str] = mapped_column(Text, primary_key=True)
    file_name: Mapped[str] = mapped_column(Text)
    file_sha256: Mapped[str] = mapped_column(Text, unique=True)
    rows_read: Mapped[int] = mapped_column(Integer, default=0)
    rows_loaded: Mapped[int] = mapped_column(Integer, default=0)
    rows_rejected: Mapped[int] = mapped_column(Integer, default=0)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SmsRecord(Base):
    __tablename__ = "sms_records"
    # Partition key must be part of the primary key. Monthly partitions are a Phase 2 task;
    # the migration creates a DEFAULT partition so inserts work now.
    message_id: Mapped[str] = mapped_column(Text, primary_key=True)
    received_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("ingest_batches.batch_id"))
    source_addr: Mapped[str] = mapped_column(Text)
    destination_addr: Mapped[str] = mapped_column(Text)
    network: Mapped[str] = mapped_column(Text)
    client_name: Mapped[str | None] = mapped_column(Text)
    country: Mapped[str | None] = mapped_column(Text)
    dlr_status: Mapped[str | None] = mapped_column(Text)
    extra: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    __table_args__ = (
        Index("ix_sms_received_time", "received_time"),
        Index("ix_sms_dest_received", "destination_addr", "received_time"),
        {"postgresql_partition_by": "RANGE (received_time)"},
    )


class RejectedRow(Base):
    __tablename__ = "rejected_rows"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("ingest_batches.batch_id"))
    line_number: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text)


class FraudRuleRow(Base):
    __tablename__ = "fraud_rules"
    rule_pk: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    rule_key: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer)
    rule_type: Mapped[str] = mapped_column(Text)
    params: Mapped[dict[str, Any]] = mapped_column(JSONB)
    weight: Mapped[float] = mapped_column(Numeric(4, 3))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    __table_args__ = (UniqueConstraint("rule_key", "version", name="uq_rule_key_version"),)


class FraudAlert(Base):
    __tablename__ = "fraud_alerts"
    alert_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    entity_type: Mapped[str] = mapped_column(Text)
    entity_key: Mapped[str] = mapped_column(Text)
    network: Mapped[str] = mapped_column(Text)
    risk_score: Mapped[float] = mapped_column(Numeric(5, 2))
    band: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    __table_args__ = (UniqueConstraint("window_start", "entity_type", "entity_key", "network",
                                       name="uq_alert_window_entity"),)


class RiskScoreComponent(Base):
    __tablename__ = "risk_score_components"
    alert_id: Mapped[int] = mapped_column(ForeignKey("fraud_alerts.alert_id", ondelete="CASCADE"),
                                          primary_key=True)
    rule_pk: Mapped[int] = mapped_column(ForeignKey("fraud_rules.rule_pk"), primary_key=True)
    severity: Mapped[float] = mapped_column(Numeric(5, 4))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB)
