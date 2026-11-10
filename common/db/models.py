"""SQLAlchemy 2.0 models for the Phase 1 schema.

The Phase 1 and Phase 2 schema has been applied and verified through Alembic on isolated test
databases. Production databases are not modified by the test suite.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey,
                        Index, Integer, Numeric, Text, UniqueConstraint, func, text)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class IngestBatch(Base):
    __tablename__ = "ingest_batches"
    batch_id: Mapped[str] = mapped_column(Text, primary_key=True)
    file_name: Mapped[str] = mapped_column(Text)
    file_sha256: Mapped[str] = mapped_column(Text, unique=True)
    rows_read: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    rows_loaded: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    rows_rejected: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
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
    extra: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default=text("'{}'"))
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
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
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
    case_id: Mapped[int | None] = mapped_column(
        ForeignKey("fraud_cases.case_id"), nullable=True
    )
    __table_args__ = (
        UniqueConstraint("window_start", "entity_type", "entity_key", "network",
                         name="uq_alert_window_entity"),
        Index("ix_alerts_case", "case_id"),
    )


class RiskScoreComponent(Base):
    __tablename__ = "risk_score_components"
    alert_id: Mapped[int] = mapped_column(ForeignKey("fraud_alerts.alert_id", ondelete="CASCADE"),
                                          primary_key=True)
    rule_pk: Mapped[int] = mapped_column(ForeignKey("fraud_rules.rule_pk"), primary_key=True)
    severity: Mapped[float] = mapped_column(Numeric(5, 4))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB)

class UserRef(Base):
    """Opaque reference to a Keycloak user; credentials remain outside this database."""
    __tablename__ = "user_refs"

    sub: Mapped[str] = mapped_column(Text, primary_key=True)
    username: Mapped[str] = mapped_column(Text, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FraudCase(Base):
    __tablename__ = "fraud_cases"

    case_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[str] = mapped_column(Text, nullable=False)
    assignee_sub: Mapped[str | None] = mapped_column(Text, nullable=True)
    outcome_label: Mapped[str | None] = mapped_column(Text, nullable=True)
    opened_by_sub: Mapped[str] = mapped_column(Text, nullable=False)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "status IN ('New','Triaged','Investigating','NeedsInfo','ConfirmedFraud','FalsePositive','Closed')",
            name="ck_case_status",
        ),
        CheckConstraint(
            "priority IN ('P1','P2','P3','P4')",
            name="ck_case_priority",
        ),
    )


class CaseEvent(Base):
    __tablename__ = "case_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(
        ForeignKey("fraud_cases.case_id"), nullable=False
    )
    from_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    to_status: Mapped[str] = mapped_column(Text, nullable=False)
    actor_sub: Mapped[str] = mapped_column(Text, nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class CaseNote(Base):
    __tablename__ = "case_notes"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(
        ForeignKey("fraud_cases.case_id"), nullable=False
    )
    author_sub: Mapped[str] = mapped_column(Text, nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditLog(Base):
    """Append-only, hash-chained audit records."""
    __tablename__ = "audit_log"

    audit_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_sub: Mapped[str | None] = mapped_column(Text, nullable=True)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    resource_type: Mapped[str] = mapped_column(Text, nullable=False)
    resource_id: Mapped[str] = mapped_column(Text, nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    prev_hash: Mapped[str] = mapped_column(Text, nullable=False)
    row_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)

    __table_args__ = (
        Index("ix_audit_at", "at"),
        Index("ix_audit_actor_at", "actor_sub", "at"),
    )
