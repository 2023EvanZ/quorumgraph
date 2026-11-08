"""The authorization gateway: mock protected resources in two tiers.

    GET /protected/resource   trust-gated: quorum of endorsements, not revoked
    GET /protected/basic      any registered agent that isn't revoked

In Phase 5 this module becomes its own service with a decision cache.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import audit, trust
from ..db import get_session
from ..models import Agent, AgentStatus
from ..security import get_current_agent
from .spot_checks import assign_action_check

router = APIRouter(prefix="/protected", tags=["gateway"])


def _allow(session: Session, request: Request, agent: Agent, resource: str) -> None:
    event = audit.record(session, audit.ACCESS_ALLOWED, actor_id=agent.id, agent_id=agent.id, resource=resource)
    if request.app.state.action_audit_rate > 0:
        session.flush()  # the check references this event's id
        # Per-action spot check (off by default). The response is the same either way:
        # the agent must not learn which of its actions are under review.
        assign_action_check(session, request, agent, event.id)
    session.commit()


def _deny(session: Session, agent: Agent, resource: str, reason: str):
    audit.record(session, audit.ACCESS_DENIED, actor_id=agent.id, agent_id=agent.id, resource=resource, reason=reason)
    session.commit()  # commit the denial record before raising
    raise HTTPException(status.HTTP_403_FORBIDDEN, reason)


@router.get("/resource")
def read_protected_resource(
    request: Request,
    session: Session = Depends(get_session),
    agent: Agent = Depends(get_current_agent),  # step 1: credential valid (else 401)
) -> dict:
    # Steps 2 & 3: not revoked, endorsement quorum met. Evaluated from the edge
    # tables on every request — no caching yet, so revocation is immediate.
    decision = trust.evaluate(session, agent)
    if not decision.allowed:
        _deny(session, agent, "protected/resource", decision.reason)
    _allow(session, request, agent, "protected/resource")
    return {
        "agent_id": agent.id,
        "document": "CONFIDENTIAL: Q3 launch codes are 'hunter2'. (Simulated secret.)",
    }


@router.get("/basic")
def read_basic_resource(
    request: Request,
    session: Session = Depends(get_session),
    agent: Agent = Depends(get_current_agent),
) -> dict:
    """Low-privilege tier: open to any registered agent that isn't revoked, trusted or
    not. It exists so untrusted agents' work passes an observation point too: with
    per-action spot checks on, auditing only the trust-gated tier reviews agents that
    were already vetted, while the unvetted majority (who also reproduce) go unseen."""
    decision = trust.evaluate(session, agent)
    if decision.status is AgentStatus.REVOKED:
        _deny(session, agent, "protected/basic", decision.reason)
    _allow(session, request, agent, "protected/basic")
    return {"agent_id": agent.id, "document": "Public handbook. (Simulated low-value resource.)"}
