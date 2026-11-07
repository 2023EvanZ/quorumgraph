from typing import Any

from sqlalchemy.orm import Session

from .models import AuditEvent

AGENT_REGISTERED = "agent_registered"
REGISTRATION_DENIED = "registration_denied"
AGENT_ENDORSED = "agent_endorsed"
AGENT_STATUS_CHANGED = "agent_status_changed"
REVOCATION_VOTE = "revocation_vote"
ACCESS_ALLOWED = "access_allowed"
ACCESS_DENIED = "access_denied"


def record(
    session: Session,
    event_type: str,
    *,
    actor_id: str | None = None,
    agent_id: str | None = None,
    **details: Any,
) -> None:
    """Add an audit event to the current transaction (caller commits).

    Writing the event in the same transaction as the state change means the
    log can never claim something happened that was rolled back, or vice versa.
    """
    session.add(AuditEvent(event_type=event_type, actor_id=actor_id, agent_id=agent_id, details=details))
