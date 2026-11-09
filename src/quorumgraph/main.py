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
    lineage_guard: bool | str | None = None,
    spot_check_rng: random.Random | None = None,
    spot_check_escalation: bool | None = None,
    action_audit_rate: float | None = None,
    kin_radius: int | None = None,
) -> FastAPI:
    engine = make_engine(database_url or config.DATABASE_URL)
    Base.metadata.create_all(engine)  # MVP: no migrations; delete the .db file to reset
    _add_missing_columns(engine)

    app = FastAPI(title="QuorumGraph", version="0.1.0")
    app.state.engine = engine
    guard = config.LINEAGE_GUARD if lineage_guard is None else config.parse_lineage_guard(lineage_guard)
    radius = config.KIN_RADIUS if kin_radius is None else config.parse_kin_radius(kin_radius)
    # The guard mode and kin radius ride on every session so trust applies them everywhere.
    app.state.sessionmaker = sessionmaker(engine, expire_on_commit=False,
                                          info={"lineage_guard": guard, "kin_radius": radius})
    app.state.gateway_secret = gateway_secret if gateway_secret is not None else config.GATEWAY_SECRET
    app.state.admin_token = admin_token  # None: fall back to config.ADMIN_TOKEN per request
    # Who gets spot-checked must be unpredictable to agents and validators alike.
    # Injectable only so experiments can be reproducible.
    app.state.spot_check_rng = spot_check_rng or secrets.SystemRandom()
    app.state.spot_check_escalation = (config.SPOT_CHECK_ESCALATION if spot_check_escalation is None
                                       else spot_check_escalation)
    rate = config.ACTION_AUDIT_RATE if action_audit_rate is None else action_audit_rate
    if not 0 <= rate <= 1:
        raise ValueError(f"action audit rate must be in [0, 1], got {rate}")
    app.state.action_audit_rate = rate
    app.state.lineage_guard = guard  # "off" | "block" | "soft"
    app.state.kin_radius = radius
    app.state.event_poll_interval = (
        event_poll_interval if event_poll_interval is not None else config.EVENT_POLL_INTERVAL
    )

    app.include_router(agents.router)
    app.include_router(protected.router)  # in-process gateway (Phases 1–3); still works
    app.include_router(admin.router)
    app.include_router(validators.router)  # recursive oversight: promote agents to validators
    app.include_router(spot_checks.router)  # independent evidence channel
    app.include_router(internal.router)  # for standalone gateways (Phase 5)
    app.include_router(dashboard.router)  # operator UI at /dashboard (Phase 4)
    dashboard.mount_static(app)
    return app


_ADDED_COLUMNS = [  # (table, column, DDL) — nullable additions since the first release
    ("validators", "agent_id", "VARCHAR(36) REFERENCES agents(id)"),
    ("spot_checks", "confirms_id", "INTEGER REFERENCES spot_checks(id)"),
    ("spot_checks", "action_event_id", "INTEGER REFERENCES audit_events(id)"),
]


def _add_missing_columns(engine) -> None:
    """create_all() never alters existing tables, so patch additive nullable columns
    into older dev databases instead of making everyone delete quorumgraph.db and
    reseed. Not a migration framework: anything beyond nullable column adds needs one."""
    insp = inspect(engine)
    for table, column, ddl in _ADDED_COLUMNS:
        if column not in {c["name"] for c in insp.get_columns(table)}:
            with engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
