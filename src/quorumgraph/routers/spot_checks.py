"""Spot checks: an evidence channel that doesn't depend on the agent's cooperation.

Why this exists: the selection experiment found that if revocation is driven only
by what an agent logs, selection favours agents that log nothing. Punishment
then targets *visibility*, not misbehaviour. A random independent check breaks
that: an opaque agent is as likely to be checked as a transparent one.

    POST /spot-checks/sample           admin: service-chosen random sample of trusted agents
                                       (include_pending: also pending ones, for deployments
                                       without an endorsement gate)
    POST /spot-checks/{id}/result      the assigned validator: passed / failed
    GET  /spot-checks                  operator: list, filter by agent or open

Design choices:
- The *service* draws the sample (app.state.spot_check_rng, SystemRandom by
  default). Neither agents nor validators can pick who is checked.
- The auditor is an active validator that did NOT endorse the agent and is not
  in its lineage: whoever vouched for an agent shouldn't be the one checking it
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

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, trust
from ..db import get_session
from ..models import Agent, AgentStatus, Endorsement, SpotCheck, Validator
from ..security import get_current_validator, get_operator, require_admin
from ..trust import is_lineage as _is_lineage
from .agents import cast_revocation_vote

router = APIRouter(prefix="/spot-checks", tags=["spot-checks"])


class SampleIn(BaseModel):
    rate: float = Field(gt=0, le=1, description="fraction of currently trusted agents to check")
    include_pending: bool = Field(False, description="also sample pending (not yet trusted) agents")
    agent_ids: list[str] | None = Field(None, max_length=10_000,
                                        description="restrict the sampling frame to these agents (e.g. the ones "
                                                    "currently deployed); the service still draws the sample")


class SpotCheckOut(BaseModel):
    id: int
    agent_id: str
    validator_id: str
    confirms_id: int | None = None
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


def _pick_auditor(session: Session, agent: Agent, rng) -> Validator | None:
    endorsers = set(session.scalars(select(Endorsement.validator_id).where(Endorsement.agent_id == agent.id)))
    active = list(session.scalars(select(Validator).where(Validator.active.is_(True)).order_by(Validator.id)))
    independent = [v for v in active if v.id not in endorsers
                   and not (v.agent_id and _is_lineage(session, ancestor_id=v.agent_id, agent=agent))]
    return rng.choice(independent) if independent else None


def _pick_confirmer(session: Session, agent: Agent, first: SpotCheck, rng) -> Validator | None:
    active = list(session.scalars(select(Validator).where(Validator.active.is_(True)).order_by(Validator.id)))
    ok = [v for v in active if v.id != first.validator_id
          and not (v.agent_id and _is_lineage(session, ancestor_id=v.agent_id, agent=agent))]
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
    follow = SpotCheck(agent_id=agent.id, validator_id=confirmer.id, confirms_id=check.id)
    session.add(follow)
    session.flush()
    audit.record(session, audit.SPOT_CHECK_ESCALATED, actor_id="service", agent_id=agent.id,
                 spot_check_id=check.id, confirmation_id=follow.id, validator_id=confirmer.id)
    return follow


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
    stmt = select(Agent).where(Agent.status.in_(wanted)).order_by(Agent.id)
    if body.agent_ids is not None:
        stmt = stmt.where(Agent.id.in_(body.agent_ids))
    candidates = session.scalars(stmt)
    created, skipped = [], 0
    for agent in candidates:
        if trust.evaluate(session, agent).status not in wanted or rng.random() >= body.rate:
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
        audit.record(session, audit.SPOT_CHECK_ASSIGNED, actor_id="admin", agent_id=agent.id,
                     validator_id=auditor.id, spot_check_id=check.id)
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
