"""Trust service app factory.

Run with:  uv run uvicorn quorumgraph.main:create_app --factory --reload

A factory (instead of a module-level ``app``) means importing this module has
no side effects, and tests can build an app against an in-memory database.
"""

import random
import secrets

from fastapi import FastAPI
from sqlalchemy import inspect, text
from sqlalchemy.orm import sessionmaker

from . import config
from .db import Base, make_engine
from .routers import admin, agents, dashboard, internal, protected, spot_checks, validators


def create_app(
    database_url: str | None = None,
    *,
    gateway_secret: str | None = None,
    event_poll_interval: float | None = None,
    admin_token: str | None = None,
    lineage_guard: bool | None = None,
    spot_check_rng: random.Random | None = None,
) -> FastAPI:
    engine = make_engine(database_url or config.DATABASE_URL)
    Base.metadata.create_all(engine)  # MVP: no migrations; delete the .db file to reset
    _add_missing_columns(engine)

    app = FastAPI(title="QuorumGraph", version="0.1.0")
    app.state.engine = engine
    app.state.sessionmaker = sessionmaker(engine, expire_on_commit=False)
    app.state.gateway_secret = gateway_secret if gateway_secret is not None else config.GATEWAY_SECRET
    app.state.admin_token = admin_token  # None: fall back to config.ADMIN_TOKEN per request
    # Who gets spot-checked must be unpredictable to agents and validators alike.
    # Injectable only so experiments can be reproducible.
    app.state.spot_check_rng = spot_check_rng or secrets.SystemRandom()
    app.state.lineage_guard = config.LINEAGE_GUARD if lineage_guard is None else lineage_guard
    app.state.event_poll_interval = (
        event_poll_interval if event_poll_interval is not None else config.EVENT_POLL_INTERVAL
    )

    app.include_router(agents.router)
    app.include_router(protected.router)  # in-process gateway (Phases 1–3); still works
    app.include_router(admin.router)
    app.include_router(validators.router)
    app.include_router(spot_checks.router)  # independent evidence channel  # recursive oversight: promote agents to validators
    app.include_router(internal.router)  # for standalone gateways (Phase 5)
    app.include_router(dashboard.router)  # operator UI at /dashboard (Phase 4)
    dashboard.mount_static(app)
    return app


def _add_missing_columns(engine) -> None:
    """create_all() never alters existing tables. One additive column has been
    added since the first release (validators.agent_id), so patch it into older
    dev databases instead of making everyone delete quorumgraph.db and reseed.
    Not a migration framework: anything beyond nullable column adds needs one."""
    cols = {c["name"] for c in inspect(engine).get_columns("validators")}
    if "agent_id" not in cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE validators ADD COLUMN agent_id VARCHAR(36) REFERENCES agents(id)"))
