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
VALIDATOR_PROMOTED = "validator_promoted"
VALIDATOR_DEACTIVATED = "validator_deactivated"
LINEAGE_ENDORSEMENT_BLOCKED = "lineage_endorsement_blocked"
SPOT_CHECK_ASSIGNED = "spot_check_assigned"
SPOT_CHECK_PASSED = "spot_check_passed"
SPOT_CHECK_FAILED = "spot_check_failed"
SPOT_CHECK_ESCALATED = "spot_check_escalated"


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
