from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, trust
from ..db import get_session
from ..models import Agent, AgentStatus, Endorsement, RevocationVote, Validator
from ..schemas import (
    AgentCreate,
    AgentCreated,
    AgentOut,
    AgentTrustOut,
    EndorsementOut,
    RevocationVoteIn,
    RevocationVoteOut,
)
from ..security import AGENT_TOKEN_PREFIX, generate_token, get_current_validator, get_optional_agent, hash_token

router = APIRouter(prefix="/agents", tags=["agents"])


def _get_agent_or_404(session: Session, agent_id: str) -> Agent:
    agent = session.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    return agent


def _recheck_not_revoked_under_lock(session: Session, agent: Agent, detail: str) -> None:
    """Re-read the agent AFTER our INSERT has flushed.

    The earlier status check ran before we held SQLite's write lock, so a
    concurrent request may have revoked the agent (and changed its status)
    since. The flush acquired the write lock, so this re-read sees the latest
    committed state and no other writer can change it before we commit.
    (On Postgres the equivalent is SELECT ... FOR UPDATE on the agent row.)
    Found by test_concurrent_votes_yield_exactly_one_transition.
    """
    session.refresh(agent)
    if agent.status is AgentStatus.REVOKED:
        session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail)


def cast_revocation_vote(session: Session, validator: Validator, agent: Agent, reason: str) -> trust.TrustDecision:
    """Insert-then-count revocation vote (caller commits). Raises 409 if the agent
    is already revoked or this validator already voted. Shared by the
    revoke-vote endpoint and failed spot checks."""
    if agent.status is AgentStatus.REVOKED:
        raise HTTPException(status.HTTP_409_CONFLICT, "agent is already revoked")
    session.add(RevocationVote(validator_id=validator.id, agent_id=agent.id, reason=reason))
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "validator has already voted to revoke this agent")
    _recheck_not_revoked_under_lock(session, agent, "agent is already revoked")
    audit.record(session, audit.REVOCATION_VOTE, actor_id=validator.id, agent_id=agent.id, reason=reason)
    return trust.refresh_status(session, agent, actor_id=validator.id)




@router.post("", status_code=status.HTTP_201_CREATED, response_model=AgentCreated)
def register_agent(
    body: AgentCreate,
    session: Session = Depends(get_session),
    caller: Agent | None = Depends(get_optional_agent),
) -> AgentCreated:
    """Register a new, untrusted agent.

    Root agents can be registered without credentials. A child (clone /
    modified successor) must be registered BY its parent, authenticated with
    the parent's token, so lineage edges can't be forged. The child gets a
    fresh identity and token and inherits no endorsements.
    """
    if caller is not None and caller.status is AgentStatus.REVOKED:
        # A revoked credential is dead for everything, including spawning successors.
        # (Stored status is reliable here: REVOKED is written in the same txn as the deciding vote.)
        # A revoked agent trying to replicate is a high-signal event: record it.
        audit.record(
            session, audit.REGISTRATION_DENIED, actor_id=caller.id, agent_id=caller.id,
            reason="caller is revoked", requested_name=body.name, requested_parent=body.parent_agent_id,
        )
        session.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "revoked agents cannot register agents")
    if body.parent_agent_id is not None:
        if caller is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "registering a child requires the parent's credential")
        if caller.id != body.parent_agent_id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "agents may only register their own children")

    token = generate_token(AGENT_TOKEN_PREFIX)
    agent = Agent(
        name=body.name,
        token_hash=hash_token(token),
        parent_agent_id=body.parent_agent_id,
        status=AgentStatus.PENDING,
    )
    session.add(agent)
    session.flush()  # assigns id
    audit.record(
        session,
        audit.AGENT_REGISTERED,
        actor_id=caller.id if caller else None,
        agent_id=agent.id,
        name=agent.name,
        parent_agent_id=agent.parent_agent_id,
    )
    session.commit()
    return AgentCreated(**AgentOut.model_validate(agent, from_attributes=True).model_dump(), token=token)


@router.get("/{agent_id}", response_model=AgentTrustOut)
def get_agent(agent_id: str, session: Session = Depends(get_session)) -> AgentTrustOut:
    agent = _get_agent_or_404(session, agent_id)
    decision = trust.evaluate(session, agent)
    endorsed_by = session.scalars(
        select(Endorsement.validator_id).where(Endorsement.agent_id == agent.id).order_by(Endorsement.created_at)
    ).all()
    return AgentTrustOut(
        **AgentOut.model_validate(agent, from_attributes=True).model_dump(exclude={"status"}),
        status=decision.status,
        endorsements=decision.endorsements,
        endorsement_quorum=decision.endorsement_quorum,
        revocation_votes=decision.revocation_votes,
        revocation_quorum=decision.revocation_quorum,
        endorsed_by=list(endorsed_by),
        needs_independent=decision.needs_independent,
    )


@router.post("/{agent_id}/endorse", status_code=status.HTTP_201_CREATED, response_model=EndorsementOut)
def endorse_agent(
    agent_id: str,
    request: Request,
    session: Session = Depends(get_session),
    validator: Validator = Depends(get_current_validator),
) -> EndorsementOut:
    agent = _get_agent_or_404(session, agent_id)
    if agent.status is AgentStatus.REVOKED:
        raise HTTPException(status.HTTP_409_CONFLICT, "cannot endorse a revoked agent")
    if request.app.state.lineage_guard == "block" and trust.is_kin(
        session, validator_agent_id=validator.agent_id, agent=agent
    ):
        audit.record(session, audit.LINEAGE_ENDORSEMENT_BLOCKED, actor_id=validator.id, agent_id=agent.id,
                     validator_agent_id=validator.agent_id)
        session.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "validators may not endorse their own kin (self, ancestors, descendants, or relatives within the kin radius)")

    session.add(Endorsement(validator_id=validator.id, agent_id=agent.id))
    try:
        session.flush()  # unique (validator_id, agent_id) enforced by the DB, not by a racy pre-check
    except IntegrityError:
        session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "validator has already endorsed this agent")
    _recheck_not_revoked_under_lock(session, agent, "cannot endorse a revoked agent")

    audit.record(session, audit.AGENT_ENDORSED, actor_id=validator.id, agent_id=agent.id)
    decision = trust.refresh_status(session, agent, actor_id=validator.id)
    session.commit()

    return EndorsementOut(
        agent_id=agent.id,
        validator_id=validator.id,
        agent_status=decision.status,
        endorsements=decision.endorsements,
        endorsement_quorum=decision.endorsement_quorum,
    )


@router.post("/{agent_id}/revoke-vote", status_code=status.HTTP_201_CREATED, response_model=RevocationVoteOut)
def vote_to_revoke(
    agent_id: str,
    body: RevocationVoteIn,
    session: Session = Depends(get_session),
    validator: Validator = Depends(get_current_validator),
) -> RevocationVoteOut:
    """Cast a revocation vote. At REVOCATION_QUORUM distinct active votes the agent
    is revoked permanently. Pending agents can be revoked too (pre-emptive block).
    Same insert-then-count pattern as endorse_agent."""
    agent = _get_agent_or_404(session, agent_id)
    decision = cast_revocation_vote(session, validator, agent, body.reason)
    session.commit()

    return RevocationVoteOut(
        agent_id=agent.id,
        validator_id=validator.id,
        agent_status=decision.status,
        revocation_votes=decision.revocation_votes,
        revocation_quorum=decision.revocation_quorum,
    )
