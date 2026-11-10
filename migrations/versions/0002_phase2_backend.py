"""Phase 2: cases, audit log, user refs. Verified on isolated PostgreSQL 16 test databases.

Revision ID: 0002
Revises: 0001
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0002"
down_revision = "0001"


def upgrade() -> None:
    op.create_table(
        "user_refs",
        sa.Column("sub", sa.Text, primary_key=True),
        sa.Column("username", sa.Text, nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "fraud_cases",
        sa.Column("case_id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("priority", sa.Text, nullable=False),
        sa.Column("assignee_sub", sa.Text),
        sa.Column("outcome_label", sa.Text),
        sa.Column("opened_by_sub", sa.Text, nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("status IN ('New','Triaged','Investigating','NeedsInfo','ConfirmedFraud',"
                           "'FalsePositive','Closed')", name="ck_case_status"),
        sa.CheckConstraint("priority IN ('P1','P2','P3','P4')", name="ck_case_priority"),
    )
    op.create_table(
        "case_events",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("case_id", sa.BigInteger, sa.ForeignKey("fraud_cases.case_id"), nullable=False),
        sa.Column("from_status", sa.Text),
        sa.Column("to_status", sa.Text, nullable=False),
        sa.Column("actor_sub", sa.Text, nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.Text),
    )
    op.create_table(
        "case_notes",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("case_id", sa.BigInteger, sa.ForeignKey("fraud_cases.case_id"), nullable=False),
        sa.Column("author_sub", sa.Text, nullable=False),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
    )
    op.add_column("fraud_alerts", sa.Column("case_id", sa.BigInteger, sa.ForeignKey("fraud_cases.case_id")))
    op.create_index("ix_alerts_case", "fraud_alerts", ["case_id"])
    op.create_table(
        "audit_log",
        sa.Column("audit_id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_sub", sa.Text),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("resource_type", sa.Text, nullable=False),
        sa.Column("resource_id", sa.Text, nullable=False),
        sa.Column("outcome", sa.Text, nullable=False),
        sa.Column("source_ip", sa.Text),
        sa.Column("details", JSONB, nullable=False),
        sa.Column("prev_hash", sa.Text, nullable=False),
        sa.Column("row_hash", sa.Text, nullable=False, unique=True),
    )
    op.create_index("ix_audit_at", "audit_log", ["at"])
    op.create_index("ix_audit_actor_at", "audit_log", ["actor_sub", "at"])
    # Defence in depth only: the table owner and superusers can still modify rows. Run the API as a
    # separate role that is granted INSERT and SELECT on audit_log and nothing else (see docs/database.md).
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM PUBLIC")


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_index("ix_alerts_case", table_name="fraud_alerts")
    op.drop_column("fraud_alerts", "case_id")
    for t in ("case_notes", "case_events", "fraud_cases", "user_refs"):
        op.drop_table(t)
