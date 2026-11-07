"""Service-to-service endpoints the trust service exposes to gateways.

- POST /internal/authorize  — authoritative decision for a token hash, plus an outbox cursor.
- GET  /internal/events     — Server-Sent Events stream of agent status changes.

The event stream is a *transactional outbox*: status-change events are the
``agent_status_changed`` rows in ``audit_events``, written in the same
transaction as the vote that caused them. The stream tails that table by id.

Why ids work as a cursor here: SQLite has a single writer, so ids are assigned
in commit order and a reader never sees id N+1 committed before id N. On
Postgres that is NOT true (sequence values are allocated before commit), and
you'd need a commit-ordered log (logical replication / CDC, or a dedicated
outbox with a "safe-to-read" watermark) instead.
"""

import asyncio
import json
import secrets
import time

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from .. import audit, trust
from ..db import get_session
from ..models import Agent, AuditEvent
from ..schemas import AuthorizeIn, AuthorizeOut

KEEPALIVE_SECONDS = 1.0


def require_gateway(request: Request, x_gateway_key: str | None = Header(default=None)) -> None:
    secret = request.app.state.gateway_secret
    if not secret:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "gateway access disabled (QG_GATEWAY_SECRET unset)")
    if x_gateway_key is None or not secrets.compare_digest(x_gateway_key.encode(), secret.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid gateway key")


router = APIRouter(prefix="/internal", tags=["internal"], dependencies=[Depends(require_gateway)])


def _head_event_id(session: Session) -> int:
    return session.scalar(select(func.max(AuditEvent.id))) or 0


@router.post("/authorize", response_model=AuthorizeOut)
def authorize(body: AuthorizeIn, session: Session = Depends(get_session)) -> AuthorizeOut:
    # Order matters: read the cursor FIRST, then compute the decision. If a
    # revocation commits in between, the decision may already reflect it (fine)
    # or not, but either way that revocation's event id is > as_of, so the
    # gateway can tell this decision might predate it. Reading in the other
    # order could stamp a stale decision with a cursor that claims it's fresh.
    as_of = _head_event_id(session)
    agent = session.scalar(select(Agent).where(Agent.token_hash == body.token_hash))
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown credential")
    d = trust.evaluate(session, agent)
    return AuthorizeOut(agent_id=agent.id, allowed=d.allowed, status=d.status, reason=d.reason, as_of_event_id=as_of)


def _sse(event: str, event_id: int, data: dict) -> str:
    return f"event: {event}\nid: {event_id}\ndata: {json.dumps(data)}\n\n"


@router.get("/events")
async def stream_events(request: Request, after: int | None = None) -> StreamingResponse:
    """Stream status changes with id > ``after``.

    Protocol:
      1. Replay every status change after the cursor (none if ``after`` omitted:
         the cursor starts at the current head).
      2. Send ``ready`` carrying the cursor. Gateways must not trust their cache
         until they see ``ready``; otherwise they'd serve entries that the
         replay is about to invalidate.
      3. Tail: poll the outbox every EVENT_POLL_INTERVAL; ``: keepalive``
         comments every second so gateways detect a dead connection quickly.
    """
    sessionmaker = request.app.state.sessionmaker
    interval = request.app.state.event_poll_interval

    def head() -> int:
        with sessionmaker() as s:
            return _head_event_id(s)

    def fetch(cursor: int) -> list[tuple[int, str, dict]]:
        with sessionmaker() as s:
            rows = s.scalars(
                select(AuditEvent)
                .where(AuditEvent.id > cursor, AuditEvent.event_type == audit.AGENT_STATUS_CHANGED)
                .order_by(AuditEvent.id)
                .limit(500)
            )
            return [(e.id, e.agent_id, e.details) for e in rows]

    async def gen():
        cursor = after if after is not None else await run_in_threadpool(head)

        while rows := await run_in_threadpool(fetch, cursor):  # 1. replay backlog
            for eid, agent_id, details in rows:
                cursor = eid
                yield _sse("status_changed", eid, {"agent_id": agent_id, "new": details["new"]})

        yield _sse("ready", cursor, {})  # 2.
        last_sent = time.monotonic()

        while not await request.is_disconnected():  # 3. tail
            for eid, agent_id, details in await run_in_threadpool(fetch, cursor):
                cursor = eid
                last_sent = time.monotonic()
                yield _sse("status_changed", eid, {"agent_id": agent_id, "new": details["new"]})
            if time.monotonic() - last_sent >= KEEPALIVE_SECONDS:
                last_sent = time.monotonic()
                yield ": keepalive\n\n"
            await asyncio.sleep(interval)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})
