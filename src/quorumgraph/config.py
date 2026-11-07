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

# --- Phase 5: distributed gateways ---------------------------------------------

# Shared secret gateways present to the trust service's /internal endpoints.
# Unset = /internal disabled (fail closed).
GATEWAY_SECRET = os.getenv("QG_GATEWAY_SECRET") or None

# How often the trust service tails the outbox for new status-change events (seconds).
EVENT_POLL_INTERVAL = float(os.getenv("QG_EVENT_POLL_INTERVAL", "0.05"))
