"""Quorum evaluation: the single place that decides whether an agent is trusted.

The source of truth is the edge tables (endorsements, revocation_votes), not
``Agent.status``. ``status`` is a materialized copy, refreshed on every write,
that exists for display and (later) for cache-invalidation events.

One exception: ``REVOKED`` is absorbing. Once the stored status is revoked it
stays revoked even if, say, a validator who voted is later deactivated.

Lineage guard "soft" mode is part of the quorum rule itself (not just the endorse
route), so every reader — endorse responses, gateways, /internal, promotion and
spot-check eligibility — sees the same answer. The mode travels on the session
(``session.info["lineage_guard"]``, set by create_app's sessionmaker); sessions made
elsewhere fall back to ``config.LINEAGE_GUARD``.
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
    needs_independent: bool = False  # soft guard: quorum met, but only by the agent's kin

    @property
    def allowed(self) -> bool:
        return self.status is AgentStatus.TRUSTED

    @property
    def reason(self) -> str:
        if self.status is AgentStatus.REVOKED:
            return "agent has been revoked"
        if self.status is AgentStatus.PENDING and self.needs_independent:
            return "endorsement quorum met only by the agent's kin; needs an independent endorser"
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


MAX_LINEAGE_DEPTH = 256


def is_lineage(session: Session, *, ancestor_id: str, agent: Agent) -> bool:
    """True if `agent` is `ancestor_id` or descends from it. Lineage edges can't be
    forged (children are registered by their parent's credential), so walking
    parent_agent_id is trustworthy. Depth-capped; cycles are impossible because a
    parent must exist before its child."""
    node: Agent | None = agent
    for _ in range(MAX_LINEAGE_DEPTH):
        if node is None:
            return False
        if node.id == ancestor_id:
            return True
        node = session.get(Agent, node.parent_agent_id) if node.parent_agent_id else None
    return True  # deeper than the cap: refuse rather than guess (fail closed)


def is_kin(session: Session, *, validator_agent_id: str | None, agent: Agent) -> bool:
    """A promoted validator is kin of `agent` if its source agent is the agent itself,
    an ancestor, or a descendant. Symmetric on purpose: a child's validator vouching
    for (or auditing) its parent is the same conflict of interest as the reverse.
    Seeded validators (no source agent) are never kin."""
    if validator_agent_id is None:
        return False
    if is_lineage(session, ancestor_id=validator_agent_id, agent=agent):
        return True
    source = session.get(Agent, validator_agent_id)
    return source is not None and is_lineage(session, ancestor_id=agent.id, agent=source)


def lineage_guard_mode(session: Session) -> str:
    return session.info.get("lineage_guard", config.LINEAGE_GUARD)


def _has_independent_endorser(session: Session, agent: Agent) -> bool:
    """At least one active endorser is a seeded validator, or a promoted one that is
    not kin (see is_kin)."""
    rows = session.execute(
        select(Validator.agent_id)
        .join(Endorsement, Endorsement.validator_id == Validator.id)
        .where(Endorsement.agent_id == agent.id, Validator.active.is_(True))
    ).all()
    return any(not is_kin(session, validator_agent_id=vid, agent=agent) for (vid,) in rows)


def evaluate(session: Session, agent: Agent) -> TrustDecision:
    endorsements = _count_active(session, Endorsement, agent.id)
    votes = _count_active(session, RevocationVote, agent.id)
    e_q, r_q = config.ENDORSEMENT_QUORUM, config.REVOCATION_QUORUM

    if agent.status is AgentStatus.REVOKED or votes >= r_q:
        status = AgentStatus.REVOKED
    elif endorsements >= e_q:
        status = AgentStatus.TRUSTED
        if lineage_guard_mode(session) == "soft" and not _has_independent_endorser(session, agent):
            return TrustDecision(AgentStatus.PENDING, endorsements, votes, e_q, r_q, needs_independent=True)
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
