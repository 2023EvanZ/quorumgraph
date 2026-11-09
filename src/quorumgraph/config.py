"""Runtime configuration, read from environment variables.

Quorum values are read at call time (``config.ENDORSEMENT_QUORUM``) rather than
imported by value, so tests can monkeypatch them.
"""

import os

DATABASE_URL = os.getenv("QG_DATABASE_URL", "sqlite:///./quorumgraph.db")

# Distinct, active validators required to trust an agent.
ENDORSEMENT_QUORUM = int(os.getenv("QG_ENDORSEMENT_QUORUM", "2"))

# Distinct, active validators required to revoke an agent.
REVOCATION_QUORUM = int(os.getenv("QG_REVOCATION_QUORUM", "2"))

# Optional operator credential for read-only admin endpoints (/audit, /graph).
# Unset = disabled; active validators can still read those endpoints.
ADMIN_TOKEN = os.getenv("QG_ADMIN_TOKEN") or None

# Lineage guard for validators that are themselves agents (promoted via POST /validators):
#   "block" (default, also "1"): a promoted validator may not endorse itself or a descendant.
#   "soft":  kin endorsements are accepted and count toward quorum, but trust also
#            requires at least one active endorser outside the agent's lineage.
#   "off"   (also "0"): no lineage rule; exists so experiments can measure the guard.
LINEAGE_GUARD_MODES = ("off", "block", "soft")


def parse_lineage_guard(value) -> str:
    """Normalize env/arg values (bools, "0"/"1", mode names) to a mode name."""
    if value is True or value in ("1", "on", "true"):
        return "block"
    if value is False or value in ("0", "false", ""):
        return "off"
    if value in LINEAGE_GUARD_MODES:
        return value
    raise ValueError(f"lineage guard must be one of {LINEAGE_GUARD_MODES}, got {value!r}")


LINEAGE_GUARD = parse_lineage_guard(os.getenv("QG_LINEAGE_GUARD", "soft").lower())


def parse_kin_radius(value) -> int:
    r = int(value)
    if r < 0:
        raise ValueError(f"kin radius must be >= 0, got {value!r}")
    return r


# Who counts as kin for the lineage guard and for picking independent auditors.
#   0 (default): direct line only (self, ancestors, descendants).
#   r > 0: also collateral relatives whose nearest common ancestor is within r
#          generations of both (1 = siblings, 2 = also first cousins, uncles/nephews).
# Wider is safer against collusion among relatives, but in a population descended from
# few roots it also makes most promoted validators count as kin.
KIN_RADIUS = parse_kin_radius(os.getenv("QG_KIN_RADIUS", "0"))

# A failed spot check is one revocation vote. With escalation on (default), the
# service also assigns a confirmation check to a second validator (not the first
# auditor, not the agent's kin; endorsers allowed, since confirming a failure goes
# against their interest). Confirmations don't escalate further, so one auditor
# still can't revoke alone. "0" = single vote only: measured to revoke only ~1–15%
# of genuinely failing agents in the selection sim, because the second vote rarely
# comes from anywhere else.
SPOT_CHECK_ESCALATION = os.getenv("QG_SPOT_CHECK_ESCALATION", "1") != "0"

# Per-action spot checks: each access the in-process gateway (/protected/resource)
# allows is audited with this probability, decided by the service at grant time and
# assigned to an independent validator to review that one action. 0 (default) = off.
# Unlike POST /spot-checks/sample (a fraction of *agents*, whenever the operator asks),
# this scales with how much an agent acts. Standalone gateways that cache decisions
# don't call the trust service per action, so they are not covered.
ACTION_AUDIT_RATE = float(os.getenv("QG_ACTION_AUDIT_RATE", "0"))

# --- Phase 5: distributed gateways ---------------------------------------------

# Shared secret gateways present to the trust service's /internal endpoints.
# Unset = /internal disabled (fail closed).
GATEWAY_SECRET = os.getenv("QG_GATEWAY_SECRET") or None

# How often the trust service tails the outbox for new status-change events (seconds).
EVENT_POLL_INTERVAL = float(os.getenv("QG_EVENT_POLL_INTERVAL", "0.05"))
