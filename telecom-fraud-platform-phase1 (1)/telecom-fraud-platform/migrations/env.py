"""Alembic environment. STATUS: unexecuted in the authoring environment."""
from alembic import context
from sqlalchemy import create_engine

from common.config import Settings
from common.db.models import Base

target_metadata = Base.metadata


def run_migrations_online() -> None:
    engine = create_engine(Settings.from_env().require_database_url())
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
