"""Database connection engine and session factory with SQLite WAL mode."""

from __future__ import annotations

import sqlite3
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from guardian.db.models import Base


def configure_sqlite_pragmas(dbapi_connection: Any, connection_record: Any) -> None:
    """Set performance and integrity pragmas on SQLite connections."""
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA busy_timeout=5000;")
        cursor.close()


def get_db_engine(
    db_url: str = "sqlite:///guardian.db",
    wal_mode: bool = True,
    echo: bool = False,
) -> Engine:
    """Create a configured SQLAlchemy engine with SQLite WAL optimizations.

    Args:
        db_url: Database connection string.
        wal_mode: Enable Write-Ahead Logging for SQLite file databases.
        echo: If True, echo SQL queries for debugging.

    Returns:
        Configured SQLAlchemy Engine.
    """
    engine = create_engine(db_url, echo=echo)

    # Attach SQLite PRAGMA listener
    event.listen(engine, "connect", configure_sqlite_pragmas)

    if wal_mode and "sqlite" in db_url and ":memory:" not in db_url:

        @event.listens_for(engine, "connect")
        def set_wal(dbapi_conn: Any, conn_record: Any) -> None:
            if isinstance(dbapi_conn, sqlite3.Connection):
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL;")
                cur.execute("PRAGMA synchronous=NORMAL;")
                cur.close()

    return engine


def get_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a scoped session maker for managing database transactions."""
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def init_db(engine: Engine) -> None:
    """Initialize database schema tables."""
    Base.metadata.create_all(bind=engine)
