"""The authorization gateway: a mock protected resource.

In Phase 5 this module becomes its own service with a decision cache.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import audit, trust
from ..db import get_session
from ..models import Agent
from ..security import get_current_agent

router = APIRouter(prefix="/protected", tags=["gateway"])


@router.get("/resource")
def read_protected_resource(
    session: Session = Depends(get_session),
    agent: Agent = Depends(get_current_agent),  # step 1: credential valid (else 401)
) -> dict:
    # Steps 2 & 3: not revoked, endorsement quorum met. Evaluated from the edge
    # tables on every request — no caching yet, so revocation is immediate.
    decision = trust.evaluate(session, agent)

    if not decision.allowed:
        audit.record(
            session, audit.ACCESS_DENIED, actor_id=agent.id, agent_id=agent.id,
            resource="protected/resource", reason=decision.reason,
        )
        session.commit()  # commit the denial record before raising
        raise HTTPException(status.HTTP_403_FORBIDDEN, decision.reason)

    audit.record(session, audit.ACCESS_ALLOWED, actor_id=agent.id, agent_id=agent.id, resource="protected/resource")
    session.commit()
    return {
        "agent_id": agent.id,
        "document": "CONFIDENTIAL: Q3 launch codes are 'hunter2'. (Simulated secret.)",
    }
