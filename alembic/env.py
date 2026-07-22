"""Alembic environment for Spotlight.

Loads the SQLAlchemy target metadata from `spotlight.store.models.Base`
and takes the database URL from the DATABASE_URL environment variable
(falling back to the sqlalchemy.url setting in alembic.ini for local
development against SQLite).

Deploy hook: run `alembic upgrade head` before starting the API / worker.
"""
from __future__ import annotations

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# Ensure the project root is on sys.path so `from spotlight...` works when
# alembic is invoked from the CLI in the repo root.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spotlight.store.models import Base  # noqa: E402

# Alembic Config object — access to the values within alembic.ini.
config = context.config

# Prefer DATABASE_URL (production) over the ini-file default. This mirrors
# the store's own URL resolution in spotlight.store.__init__.
_env_url = os.environ.get("DATABASE_URL")
if _env_url:
    # Normalize the "postgres://" scheme SQLAlchemy no longer accepts.
    if _env_url.startswith("postgres://"):
        _env_url = _env_url.replace("postgres://", "postgresql+psycopg://", 1)
    elif _env_url.startswith("postgresql://") and "+psycopg" not in _env_url:
        _env_url = _env_url.replace("postgresql://", "postgresql+psycopg://", 1)
    config.set_main_option("sqlalchemy.url", _env_url)

# Configure Python logging from alembic.ini.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# All SQLAlchemy tables in one Base — autogenerate scans this to diff
# schema vs. the database.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Generate SQL against a URL, no live DBAPI connection required."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live DB connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Detect column-type + server-default changes for autogenerate
            # so `alembic revision --autogenerate` picks them up.
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
