from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from .models import AgentStatus


class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    parent_agent_id: str | None = None


class AgentOut(BaseModel):
    id: str
    name: str
    parent_agent_id: str | None
    status: AgentStatus
    created_at: datetime


class AgentCreated(AgentOut):
    token: str = Field(description="Bearer token. Shown once; only its hash is stored.")


class AgentTrustOut(AgentOut):
    endorsements: int
    endorsement_quorum: int
    revocation_votes: int
    revocation_quorum: int
    endorsed_by: list[str]


class EndorsementOut(BaseModel):
    agent_id: str
    validator_id: str
    agent_status: AgentStatus
    endorsements: int
    endorsement_quorum: int


class RevocationVoteIn(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


class RevocationVoteOut(BaseModel):
    agent_id: str
    validator_id: str
    agent_status: AgentStatus
    revocation_votes: int
    revocation_quorum: int


class AuditEventOut(BaseModel):
    id: int
    event_type: str
    actor_id: str | None
    agent_id: str | None
    details: dict
    created_at: datetime


class GraphNode(BaseModel):
    id: str
    type: Literal["agent", "validator"]
    label: str
    status: AgentStatus | None = None  # agents only: live trust decision, same as the gateway's
    active: bool | None = None  # validators only


class GraphEdge(BaseModel):
    source: str
    target: str
    type: Literal["endorsement", "revocation_vote", "lineage"]
    # False when the edge exists but doesn't count toward quorum (its validator is inactive).
    counts: bool = True
    reason: str | None = None  # revocation votes only


class GraphOut(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


# --- Phase 5: gateway <-> trust service ------------------------------------------

class AuthorizeIn(BaseModel):
    # Gateways send the SHA-256 of the agent's token, never the token itself,
    # so the bearer secret travels no further than the first hop.
    token_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class AuthorizeOut(BaseModel):
    agent_id: str
    allowed: bool
    status: AgentStatus
    reason: str
    # Outbox cursor read BEFORE the decision was computed. Any status change not
    # reflected in this decision has a strictly greater event id.
    as_of_event_id: int
