"""Async SQLAlchemy engine/session management."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def get_engine():
    global _engine
    if _engine is None:
        url = get_settings().database_url
        connect_args = (
            {"check_same_thread": False, "timeout": 30}
            if url.startswith("sqlite")
            else {}
        )
        _engine = create_async_engine(
            url, echo=False, future=True, connect_args=connect_args
        )
        if url.startswith("sqlite"):
            from sqlalchemy import event

            @event.listens_for(_engine.sync_engine, "connect")
            def _set_sqlite_pragma(dbapi_conn, _rec):  # pragma: no cover - trivial
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA busy_timeout=30000")
                cur.execute("PRAGMA foreign_keys=ON")
                cur.close()

    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(
            get_engine(), expire_on_commit=False, class_=AsyncSession
        )
    return _sessionmaker


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding a scoped async session."""
    async with get_sessionmaker()() as session:
        yield session


async def init_db() -> None:
    """Create tables from the ORM metadata and add any missing columns (idempotent).

    ``create_all`` only creates *tables*; it never alters existing ones. The additive
    column sync below makes the documented deploy path ("new tables and columns appear
    on startup") actually true for databases created by an earlier version.
    """
    import importlib

    importlib.import_module("app.models")  # ensure ORM models are registered

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_add_missing_columns)


def _add_missing_columns(sync_conn) -> None:
    """ALTER TABLE … ADD COLUMN for ORM columns absent from an existing table."""
    from sqlalchemy import inspect as sa_inspect

    inspector = sa_inspect(sync_conn)
    dialect = sync_conn.dialect
    for table in Base.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        present = {c["name"] for c in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in present:
                continue
            col_type = column.type.compile(dialect=dialect)
            default = ""
            if column.default is not None and getattr(column.default, "is_scalar", False):
                arg = getattr(column.default, "arg", None)
                if isinstance(arg, bool):
                    default = f" DEFAULT {1 if arg else 0}"
                elif isinstance(arg, int | float):
                    default = f" DEFAULT {arg}"
                elif isinstance(arg, str):
                    default = " DEFAULT '" + arg.replace("'", "''") + "'"
            sync_conn.exec_driver_sql(
                f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {col_type}{default}'
            )


async def reset_engine() -> None:
    """Dispose the engine (used by tests to isolate DBs)."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
