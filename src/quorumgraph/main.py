"""Trust service app factory.

Run with:  uv run uvicorn quorumgraph.main:create_app --factory --reload

A factory (instead of a module-level ``app``) means importing this module has
no side effects, and tests can build an app against an in-memory database.
"""

from fastapi import FastAPI
from sqlalchemy.orm import sessionmaker

from . import config
from .db import Base, make_engine
from .routers import admin, agents, dashboard, internal, protected


def create_app(
    database_url: str | None = None,
    *,
    gateway_secret: str | None = None,
    event_poll_interval: float | None = None,
) -> FastAPI:
    engine = make_engine(database_url or config.DATABASE_URL)
    Base.metadata.create_all(engine)  # MVP: no migrations; delete the .db file to reset

    app = FastAPI(title="QuorumGraph", version="0.1.0")
    app.state.engine = engine
    app.state.sessionmaker = sessionmaker(engine, expire_on_commit=False)
    app.state.gateway_secret = gateway_secret if gateway_secret is not None else config.GATEWAY_SECRET
    app.state.event_poll_interval = (
        event_poll_interval if event_poll_interval is not None else config.EVENT_POLL_INTERVAL
    )

    app.include_router(agents.router)
    app.include_router(protected.router)  # in-process gateway (Phases 1–3); still works
    app.include_router(admin.router)
    app.include_router(internal.router)  # for standalone gateways (Phase 5)
    app.include_router(dashboard.router)  # operator UI at /dashboard (Phase 4)
    dashboard.mount_static(app)
    return app
