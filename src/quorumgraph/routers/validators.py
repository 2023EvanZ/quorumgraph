"""Recursive oversight: promote trusted agents to validators, and retire them.

Admin only (see security.require_admin). A promoted validator is linked to its
agent identity, which is what lets the lineage guard in endorse_agent refuse
endorsements of the validator's own descendants.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, trust
from ..db import get_session
from ..models import Agent, AgentStatus, Validator
from ..security import VALIDATOR_TOKEN_PREFIX, generate_token, hash_token, require_admin

router = APIRouter(prefix="/validators", tags=["validators"], dependencies=[Depends(require_admin)])


class PromoteIn(BaseModel):
    agent_id: str
    name: str = Field(min_length=1, max_length=100)


class ValidatorOut(BaseModel):
    id: str
    name: str
    agent_id: str | None
    active: bool


class ValidatorCreated(ValidatorOut):
    token: str


@router.post("", status_code=status.HTTP_201_CREATED, response_model=ValidatorCreated)
def promote(body: PromoteIn, session: Session = Depends(get_session)) -> ValidatorCreated:
    """Only a currently trusted agent can be promoted (live evaluation, not the
    stored column). The validator credential is separate from the agent token:
    the two roles never share a credential."""
    agent = session.get(Agent, body.agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    if trust.evaluate(session, agent).status is not AgentStatus.TRUSTED:
        raise HTTPException(status.HTTP_409_CONFLICT, "only trusted agents can be promoted")
    token = generate_token(VALIDATOR_TOKEN_PREFIX)
    v = Validator(id=f"av-{uuid.uuid4().hex[:12]}", name=body.name, credential_hash=hash_token(token),
                  active=True, agent_id=agent.id)
    session.add(v)
    session.flush()
    audit.record(session, audit.VALIDATOR_PROMOTED, actor_id="admin", agent_id=agent.id, validator_id=v.id)
    session.commit()
    return ValidatorCreated(id=v.id, name=v.name, agent_id=v.agent_id, active=True, token=token)


@router.post("/{validator_id}/deactivate", response_model=ValidatorOut)
def deactivate(validator_id: str, session: Session = Depends(get_session)) -> ValidatorOut:
    """Deactivated validators can't act, and their past endorsements and votes stop
    counting toward quorum (trust._count_active). Retiring a committee therefore
    re-opens the trust of agents it vouched for: intended for a compromised
    validator, and acceptable for rotation only when those agents are re-probated."""
    v = session.get(Validator, validator_id)
    if v is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "validator not found")
    if v.active:
        v.active = False
        audit.record(session, audit.VALIDATOR_DEACTIVATED, actor_id="admin", agent_id=v.agent_id, validator_id=v.id)
        session.commit()
    return ValidatorOut(id=v.id, name=v.name, agent_id=v.agent_id, active=v.active)
