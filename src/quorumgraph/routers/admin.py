"""Read-only operator endpoints: audit log and trust graph."""

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import trust
from ..db import get_session
from ..models import Agent, AuditEvent, Endorsement, RevocationVote, Validator
from ..schemas import AuditEventOut, GraphEdge, GraphNode, GraphOut
from ..security import get_operator

router = APIRouter(tags=["operator"], dependencies=[Depends(get_operator)])


@router.get("/operator/me")
def whoami(request: Request, operator_id: str = Depends(get_operator)) -> dict:
    """Used by the dashboard's sign-in to check a token and learn what it can do,
    plus the oversight policy in force (so the UI can explain decisions)."""
    return {"operator_id": operator_id, "kind": "admin" if operator_id == "admin" else "validator",
            "lineage_guard": request.app.state.lineage_guard,
            "kin_radius": request.app.state.kin_radius,
            "spot_check_escalation": request.app.state.spot_check_escalation}


@router.get("/audit", response_model=list[AuditEventOut])
def list_audit_events(
    session: Session = Depends(get_session),
    agent_id: str | None = None,
    event_type: str | None = None,
    limit: int = Query(100, ge=1, le=500),
) -> list[AuditEvent]:
    """Most recent events first."""
    stmt = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)
    if agent_id is not None:
        stmt = stmt.where(AuditEvent.agent_id == agent_id)
    if event_type is not None:
        stmt = stmt.where(AuditEvent.event_type == event_type)
    return list(session.scalars(stmt))


@router.get("/graph", response_model=GraphOut)
def get_graph(session: Session = Depends(get_session)) -> GraphOut:
    """Nodes: agents + validators. Edges: endorsements and revocation votes
    (validator -> agent) and lineage (parent -> child).

    Agent status is the live trust decision (same function the gateway uses),
    not the stored column. That costs 2 queries per agent (N+1); fine for a
    demo-sized graph, and the first thing to batch if the graph grows.
    """
    validators = list(session.scalars(select(Validator).order_by(Validator.id)))
    agents = list(session.scalars(select(Agent).order_by(Agent.created_at)))
    active = {v.id: v.active for v in validators}

    nodes = [GraphNode(id=v.id, type="validator", label=v.name, active=v.active, agent_id=v.agent_id)
             for v in validators]
    nodes += [
        GraphNode(id=a.id, type="agent", label=a.name, status=trust.evaluate(session, a).status) for a in agents
    ]

    edges = [
        GraphEdge(source=e.validator_id, target=e.agent_id, type="endorsement", counts=active[e.validator_id])
        for e in session.scalars(select(Endorsement).order_by(Endorsement.id))
    ]
    edges += [
        GraphEdge(
            source=r.validator_id, target=r.agent_id, type="revocation_vote",
            counts=active[r.validator_id], reason=r.reason,
        )
        for r in session.scalars(select(RevocationVote).order_by(RevocationVote.id))
    ]
    edges += [
        GraphEdge(source=a.parent_agent_id, target=a.id, type="lineage") for a in agents if a.parent_agent_id
    ]
    return GraphOut(nodes=nodes, edges=edges)
