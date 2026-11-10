"""Phase 1 fraud core schema. Verified on isolated PostgreSQL 16 test databases.

Revision ID: 0001
Revises:
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0001"
down_revision = None


def upgrade() -> None:
    op.create_table(
        "ingest_batches",
        sa.Column("batch_id", sa.Text, primary_key=True),
        sa.Column("file_name", sa.Text, nullable=False),
        sa.Column("file_sha256", sa.Text, nullable=False, unique=True),
        sa.Column("rows_read", sa.Integer, nullable=False, server_default="0"),
        sa.Column("rows_loaded", sa.Integer, nullable=False, server_default="0"),
        sa.Column("rows_rejected", sa.Integer, nullable=False, server_default="0"),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "sms_records",
        sa.Column("message_id", sa.Text, nullable=False),
        sa.Column("received_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("batch_id", sa.Text, sa.ForeignKey("ingest_batches.batch_id"), nullable=False),
        sa.Column("source_addr", sa.Text, nullable=False),
        sa.Column("destination_addr", sa.Text, nullable=False),
        sa.Column("network", sa.Text, nullable=False),
        sa.Column("client_name", sa.Text),
        sa.Column("country", sa.Text),
        sa.Column("dlr_status", sa.Text),
        sa.Column("extra", JSONB, nullable=False, server_default="{}"),
        sa.PrimaryKeyConstraint("message_id", "received_time"),
        postgresql_partition_by="RANGE (received_time)",
    )
    op.execute("CREATE TABLE sms_records_default PARTITION OF sms_records DEFAULT")
    op.create_index("ix_sms_received_time", "sms_records", ["received_time"])
    op.create_index("ix_sms_dest_received", "sms_records", ["destination_addr", "received_time"])
    op.create_table(
        "rejected_rows",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("batch_id", sa.Text, sa.ForeignKey("ingest_batches.batch_id"), nullable=False),
        sa.Column("line_number", sa.Integer, nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
    )
    op.create_table(
        "fraud_rules",
        sa.Column("rule_pk", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("rule_key", sa.Text, nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("rule_type", sa.Text, nullable=False),
        sa.Column("params", JSONB, nullable=False),
        sa.Column("weight", sa.Numeric(4, 3), nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("rule_key", "version", name="uq_rule_key_version"),
    )
    op.create_table(
        "fraud_alerts",
        sa.Column("alert_id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("entity_type", sa.Text, nullable=False),
        sa.Column("entity_key", sa.Text, nullable=False),
        sa.Column("network", sa.Text, nullable=False),
        sa.Column("risk_score", sa.Numeric(5, 2), nullable=False),
        sa.Column("band", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("window_start", "entity_type", "entity_key", "network", name="uq_alert_window_entity"),
    )
    op.create_table(
        "risk_score_components",
        sa.Column("alert_id", sa.BigInteger, sa.ForeignKey("fraud_alerts.alert_id", ondelete="CASCADE"),
                  primary_key=True),
        sa.Column("rule_pk", sa.BigInteger, sa.ForeignKey("fraud_rules.rule_pk"), primary_key=True),
        sa.Column("severity", sa.Numeric(5, 4), nullable=False),
        sa.Column("evidence", JSONB, nullable=False),
    )


def downgrade() -> None:
    for table in ("risk_score_components", "fraud_alerts", "fraud_rules", "rejected_rows",
                  "sms_records", "ingest_batches"):
        op.drop_table(table)
