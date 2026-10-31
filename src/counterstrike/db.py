"""SQLAlchemy engine and unit-of-work helpers for the persistent service."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from functools import lru_cache

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from counterstrike.config import PROJECT_ROOT, Settings, load_settings


@lru_cache(maxsize=4)
def _engine_for_url(database_url: str) -> Engine:
    return create_engine(database_url, pool_pre_ping=True, future=True)


def get_engine(settings: Settings | None = None) -> Engine:
    settings = settings or load_settings()
    if settings.database_url is None:
        raise RuntimeError("DATABASE_URL must be configured for database-backed operations")
    return _engine_for_url(settings.database_url.get_secret_value())


def get_session_factory(settings: Settings | None = None) -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(settings), autoflush=False, expire_on_commit=False)


def database_readiness(settings: Settings) -> str:
    """Return a non-sensitive readiness category without exposing connection details."""
    if settings.database_url is None:
        return "fixture_mode"
    try:
        engine = get_engine(settings)
        migration_config = PROJECT_ROOT / "alembic.ini"
        if not migration_config.is_file():
            return "not_migrated"
        config = Config(str(migration_config))
        config.set_main_option("script_location", str(migration_config.parent / "migrations"))
        script = ScriptDirectory.from_config(config)
        expected_heads = set(script.get_heads())
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            if not inspect(connection).has_table("alembic_version"):
                return "not_migrated"
            applied_heads = set(MigrationContext.configure(connection).get_current_heads())
        if not expected_heads or applied_heads != expected_heads:
            return "not_migrated"
        return "ready"
    except Exception:
        return "unreachable"


@contextmanager
def session_scope(settings: Settings | None = None) -> Generator[Session, None, None]:
    """Commit on success and roll back on failure; callers own the transaction boundary."""
    factory = get_session_factory(settings)
    with factory() as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
