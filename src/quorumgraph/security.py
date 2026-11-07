"""Credential generation, hashing, and FastAPI auth dependencies.

Tokens are 256-bit random values, so a fast hash (SHA-256) is appropriate:
slow password hashes (bcrypt/argon2) exist to resist brute-forcing *low-entropy*
human passwords, which doesn't apply here. A deterministic hash also lets us
look tokens up by an indexed column instead of scanning every row.

Agent and validator credentials live in different tables and are resolved by
different dependencies, so an agent token can never authenticate as a
validator. That is what makes "an agent cannot endorse itself" structural
rather than a runtime check.
"""

import hashlib
import secrets

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config
from .db import get_session
from .models import Agent, Validator

AGENT_TOKEN_PREFIX = "qga"
VALIDATOR_TOKEN_PREFIX = "qgv"

_bearer = HTTPBearer(auto_error=False)


def generate_token(prefix: str) -> str:
    # The prefix makes leaked tokens identifiable (e.g., by secret scanners).
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_optional_agent(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: Session = Depends(get_session),
) -> Agent | None:
    """Resolve an agent if a bearer token is present; raise 401 if it's present but invalid."""
    if creds is None:
        return None
    agent = session.scalar(select(Agent).where(Agent.token_hash == hash_token(creds.credentials)))
    if agent is None:
        raise _unauthorized("invalid agent credential")
    return agent


def get_current_agent(agent: Agent | None = Depends(get_optional_agent)) -> Agent:
    if agent is None:
        raise _unauthorized("missing agent credential")
    return agent


def get_current_validator(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: Session = Depends(get_session),
) -> Validator:
    if creds is None:
        raise _unauthorized("missing validator credential")
    validator = session.scalar(
        select(Validator).where(Validator.credential_hash == hash_token(creds.credentials))
    )
    if validator is None or not validator.active:
        raise _unauthorized("invalid or inactive validator credential")
    return validator


def _admin_token(request: Request) -> str | None:
    return request.app.state.admin_token or config.ADMIN_TOKEN


def _is_admin(request: Request, token: str) -> bool:
    admin = _admin_token(request)
    return bool(admin) and secrets.compare_digest(token.encode(), admin.encode())


def require_admin(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> str:
    """Admin only. Validators deliberately can't promote validators: otherwise a
    captured committee could appoint its own successors."""
    if creds is None or not _is_admin(request, creds.credentials):
        raise _unauthorized("admin credential required")
    return "admin"


def get_operator(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: Session = Depends(get_session),
) -> str:
    """Read access to operational data (/audit, /graph): the admin token or any
    active validator. Agents are deliberately excluded: the audit log reveals
    who voted against whom, which a compromised agent shouldn't learn.
    Returns the operator's id ("admin" or the validator id)."""
    if creds is None:
        raise _unauthorized("missing operator credential")
    token = creds.credentials
    if _is_admin(request, token):
        return "admin"
    validator = session.scalar(select(Validator).where(Validator.credential_hash == hash_token(token)))
    if validator is None or not validator.active:
        raise _unauthorized("invalid operator credential")
    return validator.id
