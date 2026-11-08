"""Spot checks: an evidence channel that doesn't depend on the agent's cooperation.

Why this exists: the selection experiment found that if revocation is driven only
by what an agent logs, selection favours agents that log nothing. Punishment
then targets *visibility*, not misbehaviour. A random independent check breaks
that: an opaque agent is as likely to be checked as a transparent one.

    POST /spot-checks/sample           admin: service-chosen random sample of trusted agents
                                       (include_pending: also pending ones, for deployments
                                       without an endorsement gate; weighting="lineage":
                                       same budget, tilted toward successors of flagged agents)
    POST /spot-checks/{id}/result      the assigned validator: passed / failed
    GET  /spot-checks                  operator: list, filter by agent or open

Per-action checks (app.state.action_audit_rate > 0): the in-process gateway calls
assign_action_check() on each access it allows, and with that probability opens a
check on *that action* (action_event_id = its access_allowed audit event). The
agent's response is identical either way, so it can't tell which actions are
reviewed. Why: agent-level sampling reviews a fraction of agents once, whenever the
operator asks, so a heavy defector is no likelier to be checked than a light one.
Per-action sampling scales with how much an agent acts, and a failure can revoke
it mid-stream, before the rest of its gated actions.

Design choices:
- The *service* draws the sample (app.state.spot_check_rng, SystemRandom by
  default). Neither agents nor validators can pick who is checked.
- The auditor is an active validator that did NOT endorse the agent and is not
  its kin (trust.is_kin: promoted from the agent, an ancestor, or a descendant): whoever vouched for an agent shouldn't be the one checking it
  (the double-entry idea: two independent records).
- A failure is exactly one revocation vote from the auditor. Revocation still
  needs quorum, so a single corrupt auditor can't revoke anyone alone.
- Escalation (config.SPOT_CHECK_ESCALATION, default on): a failure also creates a
  confirmation check for a second validator: not the first auditor, not kin,
  endorsers allowed (confirming a failure is against their interest, so their
  bias runs the safe way). Its failure is the second vote; it never escalates
  again. Without this, the selection sim showed only ~1–15% of genuinely failing
  agents were ever revoked: the second vote almost never came from elsewhere.
"""

from collections import Counter
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit, trust
from ..db import get_session
from ..models import Agent, AgentStatus, Endorsement, RevocationVote, SpotCheck, Validator
from ..security import get_current_validator, get_operator, require_admin
from ..trust import is_kin
from .agents import cast_revocation_vote

router = APIRouter(prefix="/spot-checks", tags=["spot-checks"])


class SampleIn(BaseModel):
    rate: float = Field(gt=0, le=1, description="fraction of currently trusted agents to check")
    include_pending: bool = Field(False, description="also sample pending (not yet trusted) agents")
    agent_ids: list[str] | None = Field(None, max_length=10_000,
                                        description="restrict the sampling frame to these agents (e.g. the ones "
                                                    "currently deployed); the service still draws the sample")
    weighting: Literal["uniform", "lineage"] = Field(
        "uniform", description="lineage: same expected number of checks, but agents whose recent ancestors "
                               "failed spot checks or drew revocation votes are more likely to be picked")


LINEAGE_DEPTH = 3     # ancestors looked at: parent, grandparent, great-grandparent
LINEAGE_DECAY = 0.5   # each generation further back counts half as much


class SpotCheckOut(BaseModel):
    id: int
    agent_id: str
    validator_id: str
    confirms_id: int | None = None
    action_event_id: int | None = None  # per-action check: the access_allowed event under review
    result: str | None
    notes: str
    created_at: datetime
    resolved_at: datetime | None


class ResultIn(BaseModel):
    passed: bool
    notes: str = Field("", max_length=500)


class ResultOut(SpotCheckOut):
    agent_status: str
    confirmation: SpotCheckOut | None = None  # escalated follow-up, if one was assigned


def _out(c: SpotCheck) -> SpotCheckOut:
    return SpotCheckOut.model_validate(c, from_attributes=True)


def _active_validators(session: Session) -> list[Validator]:
    """Active validators in a stable order (seeded by id, then promoted by when their
    agent was created). Promoted ids are random, so ordering by id would make the
    rng's choice depend on uuid luck and experiments with a seeded rng irreproducible."""
    rows = session.execute(
        select(Validator, Agent.created_at).outerjoin(Agent, Agent.id == Validator.agent_id)
        .where(Validator.active.is_(True))
    ).all()
    rows.sort(key=lambda r: (r[1] is not None, r[1] or datetime.min.replace(tzinfo=timezone.utc), r[0].id))
    return [v for v, _ in rows]


def _pick_auditor(session: Session, agent: Agent, rng) -> Validator | None:
    endorsers = set(session.scalars(select(Endorsement.validator_id).where(Endorsement.agent_id == agent.id)))
    active = _active_validators(session)
    independent = [v for v in active if v.id not in endorsers
                   and not is_kin(session, validator_agent_id=v.agent_id, agent=agent)]
    return rng.choice(independent) if independent else None


def _pick_confirmer(session: Session, agent: Agent, first: SpotCheck, rng) -> Validator | None:
    active = _active_validators(session)
    ok = [v for v in active if v.id != first.validator_id
          and not is_kin(session, validator_agent_id=v.agent_id, agent=agent)]
    return rng.choice(ok) if ok else None


def _escalate(session: Session, request: Request, check: SpotCheck, agent: Agent) -> SpotCheck | None:
    if (not request.app.state.spot_check_escalation or check.confirms_id is not None
            or agent.status is AgentStatus.REVOKED):
        return None
    confirmer = _pick_confirmer(session, agent, check, request.app.state.spot_check_rng)
    if confirmer is None:
        audit.record(session, audit.SPOT_CHECK_ESCALATED, actor_id="service", agent_id=agent.id,
                     spot_check_id=check.id, validator_id=None, skipped="no second validator")
        return None
    follow = SpotCheck(agent_id=agent.id, validator_id=confirmer.id, confirms_id=check.id,
                       action_event_id=check.action_event_id)  # the confirmer reviews the same action
    session.add(follow)
    session.flush()
    audit.record(session, audit.SPOT_CHECK_ESCALATED, actor_id="service", agent_id=agent.id,
                 spot_check_id=check.id, confirmation_id=follow.id, validator_id=confirmer.id)
    return follow


def assign_action_check(session: Session, request: Request, agent: Agent, action_event_id: int) -> SpotCheck | None:
    """Called by the gateway for each allowed access. With prob action_audit_rate, open
    a check on that action, assigned like any other (independent of endorsers and kin).
    The caller commits, in the same transaction as the access_allowed event."""
    rate = request.app.state.action_audit_rate
    if rate <= 0:
        return None
    rng = request.app.state.spot_check_rng
    if rng.random() >= rate:
        return None
    auditor = _pick_auditor(session, agent, rng)
    if auditor is None:
        audit.record(session, audit.SPOT_CHECK_ASSIGNED, actor_id="service", agent_id=agent.id,
                     validator_id=None, action_event_id=action_event_id, skipped="no independent validator")
        return None
    check = SpotCheck(agent_id=agent.id, validator_id=auditor.id, action_event_id=action_event_id)
    session.add(check)
    session.flush()
    audit.record(session, audit.SPOT_CHECK_ASSIGNED, actor_id="service", agent_id=agent.id,
                 validator_id=auditor.id, spot_check_id=check.id, action_event_id=action_event_id)
    return check


def _suspicion(session: Session, agents: list[Agent]) -> dict[str, float]:
    """Per agent: decayed count of failed spot checks + revocation votes on its recent
    ancestors. Only evidence the service itself holds; the agent's own record is not
    used (a fresh identity has none, and trust is never inherited, but scrutiny is)."""
    fails = Counter(dict(session.execute(
        select(SpotCheck.agent_id, func.count()).where(SpotCheck.result == "failed").group_by(SpotCheck.agent_id)
    ).all()))
    votes = Counter(dict(session.execute(
        select(RevocationVote.agent_id, func.count()).group_by(RevocationVote.agent_id)
    ).all()))
    parent_of: dict[str, str | None] = {}

    def parent(aid: str) -> str | None:
        if aid not in parent_of:
            a = session.get(Agent, aid)
            parent_of[aid] = a.parent_agent_id if a else None
        return parent_of[aid]

    out = {}
    for a in agents:
        score, node, w = 0.0, a.parent_agent_id, 1.0
        for _ in range(LINEAGE_DEPTH):
            if node is None:
                break
            score += w * (fails[node] + votes[node])
            node, w = parent(node), w * LINEAGE_DECAY
        out[a.id] = score
    return out


def _inclusion_probs(rate: float, weights: list[float]) -> list[float]:
    """p_i proportional to w_i with sum(p) = rate * n (the uniform budget), capped at 1;
    capped excess is spread over the rest (water-filling)."""
    n = len(weights)
    budget, probs, free = rate * n, [0.0] * n, list(range(n))
    while free:
        total = sum(weights[i] for i in free)
        scale = budget / total if total > 0 else 0.0
        over = [i for i in free if weights[i] * scale >= 1]
        if not over:
            for i in free:
                probs[i] = weights[i] * scale
            break
        for i in over:
            probs[i] = 1.0
        budget -= len(over)
        free = [i for i in free if i not in set(over)]
    return probs


@router.post("/sample", status_code=status.HTTP_201_CREATED, response_model=list[SpotCheckOut],
             dependencies=[Depends(require_admin)])
def sample(body: SampleIn, request: Request, response: Response,
           session: Session = Depends(get_session)) -> list[SpotCheckOut]:
    """Each currently trusted agent (and pending, if asked) is checked independently
    with prob `rate`. Agents with no independent validator available are skipped;
    that is recorded and counted in the X-Spot-Checks-Skipped header, since it means
    the committee is too small or too entangled to audit them."""
    rng = request.app.state.spot_check_rng
    wanted = {AgentStatus.TRUSTED, AgentStatus.PENDING} if body.include_pending else {AgentStatus.TRUSTED}
    stmt = select(Agent).where(Agent.status.in_(wanted)).order_by(Agent.created_at, Agent.id)
    if body.agent_ids is not None:
        stmt = stmt.where(Agent.id.in_(body.agent_ids))
    candidates = list(session.scalars(stmt))
    if body.agent_ids is not None:  # walk the caller's order (stable), not uuid order
        rank = {aid: i for i, aid in enumerate(dict.fromkeys(body.agent_ids))}
        candidates.sort(key=lambda a: rank[a.id])
    created, skipped = [], 0
    if body.weighting == "lineage":
        candidates = [a for a in candidates if trust.evaluate(session, a).status in wanted]
        susp = _suspicion(session, candidates)
        probs = dict(zip((a.id for a in candidates),
                         _inclusion_probs(body.rate, [1.0 + susp[a.id] for a in candidates])))
    for agent in candidates:
        if body.weighting == "lineage":
            if rng.random() >= probs[agent.id]:
                continue
        elif trust.evaluate(session, agent).status not in wanted or rng.random() >= body.rate:
            continue
        auditor = _pick_auditor(session, agent, rng)
        if auditor is None:
            skipped += 1
            audit.record(session, audit.SPOT_CHECK_ASSIGNED, actor_id="admin", agent_id=agent.id,
                         validator_id=None, skipped="no independent validator")
            continue
        check = SpotCheck(agent_id=agent.id, validator_id=auditor.id)
        session.add(check)
        session.flush()
        extra = {"inclusion_prob": round(probs[agent.id], 4)} if body.weighting == "lineage" else {}
        audit.record(session, audit.SPOT_CHECK_ASSIGNED, actor_id="admin", agent_id=agent.id,
                     validator_id=auditor.id, spot_check_id=check.id, **extra)
        created.append(check)
    session.commit()
    response.headers["X-Spot-Checks-Skipped"] = str(skipped)
    return [_out(c) for c in created]


@router.post("/{check_id}/result", response_model=ResultOut)
def submit_result(
    check_id: int,
    body: ResultIn,
    request: Request,
    session: Session = Depends(get_session),
    validator: Validator = Depends(get_current_validator),
) -> ResultOut:
    check = session.get(SpotCheck, check_id)
    if check is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "spot check not found")
    if check.validator_id != validator.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only the assigned validator can resolve this check")
    if check.result is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "spot check already resolved")
    agent = session.get(Agent, check.agent_id)

    check.result = "passed" if body.passed else "failed"
    check.notes = body.notes
    check.resolved_at = datetime.now(timezone.utc)
    if body.passed:
        audit.record(session, audit.SPOT_CHECK_PASSED, actor_id=validator.id, agent_id=agent.id, spot_check_id=check.id)
        decision = trust.evaluate(session, agent)
    else:
        audit.record(session, audit.SPOT_CHECK_FAILED, actor_id=validator.id, agent_id=agent.id,
                     spot_check_id=check.id, notes=body.notes)
        if agent.status is AgentStatus.REVOKED:
            decision = trust.evaluate(session, agent)  # already out; the failure is still on record
        else:
            try:
                decision = cast_revocation_vote(session, validator, agent, f"failed spot check #{check.id}")
            except HTTPException as e:
                if e.status_code != status.HTTP_409_CONFLICT:
                    raise
                # already voted, or revoked concurrently: re-apply the result, keep the record
                session.rollback()
                check = session.get(SpotCheck, check_id)
                check.result, check.notes, check.resolved_at = "failed", body.notes, datetime.now(timezone.utc)
                audit.record(session, audit.SPOT_CHECK_FAILED, actor_id=validator.id, agent_id=agent.id,
                             spot_check_id=check.id, notes=body.notes)
                decision = trust.evaluate(session, session.get(Agent, check.agent_id))
                agent = session.get(Agent, check.agent_id)
    follow = None
    if not body.passed and decision.status is not AgentStatus.REVOKED:
        follow = _escalate(session, request, check, agent)
    session.commit()
    return ResultOut(**_out(check).model_dump(), agent_status=decision.status.value,
                     confirmation=_out(follow) if follow else None)


@router.get("", response_model=list[SpotCheckOut], dependencies=[Depends(get_operator)])
def list_checks(
    session: Session = Depends(get_session),
    agent_id: str | None = None,
    open_only: bool = False,
    limit: int = Query(100, ge=1, le=500),
) -> list[SpotCheckOut]:
    stmt = select(SpotCheck).order_by(SpotCheck.id.desc()).limit(limit)
    if agent_id:
        stmt = stmt.where(SpotCheck.agent_id == agent_id)
    if open_only:
        stmt = stmt.where(SpotCheck.result.is_(None))
    return [_out(c) for c in session.scalars(stmt)]
