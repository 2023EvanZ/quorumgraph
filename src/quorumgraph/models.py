import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AgentStatus(str, enum.Enum):
    PENDING = "pending"
    TRUSTED = "trusted"
    REVOKED = "revoked"


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(100))
    # SHA-256 hex of the bearer token. The plaintext token is never stored.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    parent_agent_id: Mapped[str | None] = mapped_column(ForeignKey("agents.id"), nullable=True, index=True)
    # Materialized view of trust state, refreshed on every endorsement/revocation write.
    # The gateway does NOT trust this column alone; see trust.evaluate().
    status: Mapped[AgentStatus] = mapped_column(
        Enum(AgentStatus, native_enum=False, length=16), default=AgentStatus.PENDING
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Validator(Base):
    __tablename__ = "validators"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. "validator-a"
    name: Mapped[str] = mapped_column(String(100))
    credential_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Set when the validator is a promoted agent (recursive oversight). Seeded,
    # external validators have no agent identity.
    agent_id: Mapped[str | None] = mapped_column(ForeignKey("agents.id"), nullable=True, index=True)


class Endorsement(Base):
    """Directed trust edge: validator -> agent."""

    __tablename__ = "endorsements"
    __table_args__ = (UniqueConstraint("validator_id", "agent_id", name="uq_endorsement"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    validator_id: Mapped[str] = mapped_column(ForeignKey("validators.id"), index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RevocationVote(Base):
    __tablename__ = "revocation_votes"
    __table_args__ = (UniqueConstraint("validator_id", "agent_id", name="uq_revocation_vote"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    validator_id: Mapped[str] = mapped_column(ForeignKey("validators.id"), index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SpotCheck(Base):
    """An independent check of a trusted agent, chosen by the trust service's own
    randomness and assigned to a validator who didn't endorse it. Evidence that
    doesn't depend on the agent's cooperation (its own logs). result: NULL until
    resolved, then "passed" or "failed"."""

    __tablename__ = "spot_checks"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    validator_id: Mapped[str] = mapped_column(ForeignKey("validators.id"), index=True)
    result: Mapped[str | None] = mapped_column(String(16), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Set on a confirmation check: the failed check it was escalated from.
    confirms_id: Mapped[int | None] = mapped_column(ForeignKey("spot_checks.id"), nullable=True)


class AuditEvent(Base):
    """Append-only log. Nothing in the app updates or deletes these rows."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    actor_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
