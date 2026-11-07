from collections.abc import Iterator

from fastapi import Request
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def make_engine(url: str) -> Engine:
    kwargs: dict = {}
    is_sqlite = url.startswith("sqlite")
    if is_sqlite:
        # FastAPI runs sync endpoints in a threadpool, so connections cross threads.
        kwargs["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            # In-memory DB lives inside one connection; share it across the pool.
            kwargs["poolclass"] = StaticPool

    engine = create_engine(url, **kwargs)

    if is_sqlite:
        @event.listens_for(engine, "connect")
        def _enable_foreign_keys(dbapi_conn, _record):  # SQLite ignores FKs by default
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return engine


def get_session(request: Request) -> Iterator[Session]:
    """FastAPI dependency: one session per request. Routes commit explicitly."""
    with request.app.state.sessionmaker() as session:
        yield session
