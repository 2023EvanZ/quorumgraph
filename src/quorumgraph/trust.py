"""Quorum evaluation: the single place that decides whether an agent is trusted.

The source of truth is the edge tables (endorsements, revocation_votes), not
``Agent.status``. ``status`` is a materialized copy, refreshed on every write,
that exists for display and (later) for cache-invalidation events.

One exception: ``REVOKED`` is absorbing. Once the stored status is revoked it
stays revoked even if, say, a validator who voted is later deactivated.
"""

from dataclasses import dataclass

from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from . import audit, config
from .models import Agent, AgentStatus, Endorsement, RevocationVote, Validator


@dataclass(frozen=True)
class TrustDecision:
    status: AgentStatus
    endorsements: int
    revocation_votes: int
    endorsement_quorum: int
    revocation_quorum: int

    @property
    def allowed(self) -> bool:
        return self.status is AgentStatus.TRUSTED

    @property
    def reason(self) -> str:
        if self.status is AgentStatus.REVOKED:
            return "agent has been revoked"
        if self.status is AgentStatus.PENDING:
            return f"endorsement quorum not met ({self.endorsements}/{self.endorsement_quorum})"
        return "endorsement quorum met"


def _count_active(session: Session, edge_model, agent_id: str) -> int:
    """Count DISTINCT active validators with an edge of this type to the agent."""
    stmt = (
        select(func.count(distinct(edge_model.validator_id)))
        .join(Validator, Validator.id == edge_model.validator_id)
        .where(edge_model.agent_id == agent_id, Validator.active.is_(True))
    )
    return session.scalar(stmt) or 0


def evaluate(session: Session, agent: Agent) -> TrustDecision:
    endorsements = _count_active(session, Endorsement, agent.id)
    votes = _count_active(session, RevocationVote, agent.id)
    e_q, r_q = config.ENDORSEMENT_QUORUM, config.REVOCATION_QUORUM

    if agent.status is AgentStatus.REVOKED or votes >= r_q:
        status = AgentStatus.REVOKED
    elif endorsements >= e_q:
        status = AgentStatus.TRUSTED
    else:
        status = AgentStatus.PENDING

    return TrustDecision(status, endorsements, votes, e_q, r_q)


def refresh_status(session: Session, agent: Agent, *, actor_id: str | None) -> TrustDecision:
    """Recompute trust after a write and persist any transition (caller commits).

    Call this AFTER inserting the new edge and flushing. On SQLite the INSERT
    takes the write lock, so the counts here see every committed edge and a
    concurrent writer cannot interleave between our insert and our count.
    """
    decision = evaluate(session, agent)
    if decision.status is not agent.status:
        audit.record(
            session,
            audit.AGENT_STATUS_CHANGED,
            actor_id=actor_id,
            agent_id=agent.id,
            old=agent.status.value,
            new=decision.status.value,
            endorsements=decision.endorsements,
            revocation_votes=decision.revocation_votes,
        )
        agent.status = decision.status
    return decision
