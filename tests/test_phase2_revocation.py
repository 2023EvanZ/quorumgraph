"""Phase 2: quorum revocation, audit endpoint, graph endpoint, concurrency."""

from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from quorumgraph import config
from quorumgraph.main import create_app
from quorumgraph.models import AuditEvent, Validator
from quorumgraph.seed import seed_validators

from .conftest import access, bearer, endorse, register, revoke


@pytest.fixture
def trusted_alpha(client, validators) -> dict:
    alpha = register(client, "alpha")
    endorse(client, alpha["id"], validators["validator-a"])
    endorse(client, alpha["id"], validators["validator-b"])
    assert access(client, alpha["token"]).status_code == 200
    return alpha


# --- Revocation quorum ---------------------------------------------------------

def test_one_revocation_vote_is_not_enough(client, validators, trusted_alpha):
    resp = revoke(client, trusted_alpha["id"], validators["validator-a"])
    assert resp.status_code == 201
    assert resp.json()["agent_status"] == "trusted"
    assert resp.json()["revocation_votes"] == 1
    assert access(client, trusted_alpha["token"]).status_code == 200


def test_two_revocation_votes_revoke_immediately(client, validators, trusted_alpha):
    revoke(client, trusted_alpha["id"], validators["validator-a"])
    resp = revoke(client, trusted_alpha["id"], validators["validator-c"])
    assert resp.json()["agent_status"] == "revoked"

    denied = access(client, trusted_alpha["token"])
    assert denied.status_code == 403
    assert denied.json()["detail"] == "agent has been revoked"
    assert client.get(f"/agents/{trusted_alpha['id']}").json()["status"] == "revoked"


def test_duplicate_revocation_vote_rejected_and_not_double_counted(client, validators, trusted_alpha):
    revoke(client, trusted_alpha["id"], validators["validator-a"])
    assert revoke(client, trusted_alpha["id"], validators["validator-a"]).status_code == 409
    assert client.get(f"/agents/{trusted_alpha['id']}").json()["revocation_votes"] == 1
    assert access(client, trusted_alpha["token"]).status_code == 200


def test_revocation_is_absorbing(client, validators, trusted_alpha, db):
    revoke(client, trusted_alpha["id"], validators["validator-a"])
    revoke(client, trusted_alpha["id"], validators["validator-c"])

    # Further votes and endorsements are refused...
    assert revoke(client, trusted_alpha["id"], validators["validator-b"]).status_code == 409
    assert endorse(client, trusted_alpha["id"], validators["validator-c"]).status_code == 409

    # ...and deactivating a voter (vote count drops to 1) does NOT un-revoke.
    db.get(Validator, "validator-c").active = False
    db.commit()
    assert access(client, trusted_alpha["token"]).status_code == 403


def test_pending_agent_can_be_preemptively_revoked(client, validators):
    agent = register(client, "suspicious")
    revoke(client, agent["id"], validators["validator-a"])
    assert revoke(client, agent["id"], validators["validator-b"]).json()["agent_status"] == "revoked"
    assert endorse(client, agent["id"], validators["validator-c"]).status_code == 409


def test_revocation_requires_validator_auth_and_reason(client, validators, trusted_alpha):
    agent_id = trusted_alpha["id"]
    # Agent can't vote (on itself or anyone).
    assert revoke(client, agent_id, trusted_alpha["token"]).status_code == 401
    assert client.post(f"/agents/{agent_id}/revoke-vote", json={"reason": "x"}).status_code == 401
    # Reason is mandatory: revocations must be explainable.
    resp = client.post(
        f"/agents/{agent_id}/revoke-vote", json={"reason": ""}, headers=bearer(validators["validator-a"])
    )
    assert resp.status_code == 422
    assert revoke(client, "nope", validators["validator-a"]).status_code == 404


def test_revoked_agent_cannot_spawn_children(client, validators, trusted_alpha):
    revoke(client, trusted_alpha["id"], validators["validator-a"])
    revoke(client, trusted_alpha["id"], validators["validator-c"])
    resp = client.post(
        "/agents",
        json={"name": "escape-pod", "parent_agent_id": trusted_alpha["id"]},
        headers=bearer(trusted_alpha["token"]),
    )
    assert resp.status_code == 403


def test_revoking_parent_does_not_affect_independently_trusted_child(client, validators, trusted_alpha):
    """MVP policy: lineage is recorded but revocation does not cascade (Phase 5 option)."""
    beta = register(client, "beta", parent_id=trusted_alpha["id"], token=trusted_alpha["token"])
    endorse(client, beta["id"], validators["validator-a"])
    endorse(client, beta["id"], validators["validator-c"])
    revoke(client, trusted_alpha["id"], validators["validator-a"])
    revoke(client, trusted_alpha["id"], validators["validator-c"])

    assert access(client, trusted_alpha["token"]).status_code == 403
    assert access(client, beta["token"]).status_code == 200


# --- Audit endpoint ------------------------------------------------------------

def test_audit_endpoint_returns_full_revocation_story(client, validators, trusted_alpha):
    revoke(client, trusted_alpha["id"], validators["validator-a"], reason="exfiltration attempt")
    revoke(client, trusted_alpha["id"], validators["validator-c"], reason="confirmed")
    access(client, trusted_alpha["token"])

    resp = client.get("/audit", params={"agent_id": trusted_alpha["id"]}, headers=bearer(validators["validator-b"]))
    assert resp.status_code == 200
    events = list(reversed(resp.json()))  # endpoint is newest-first
    assert [e["event_type"] for e in events] == [
        "agent_registered",
        "agent_endorsed",
        "agent_endorsed",
        "agent_status_changed",  # pending -> trusted
        "access_allowed",
        "revocation_vote",
        "revocation_vote",
        "agent_status_changed",  # trusted -> revoked
        "access_denied",
    ]
    assert events[5]["details"]["reason"] == "exfiltration attempt"
    assert events[7]["details"] == {
        "old": "trusted", "new": "revoked", "endorsements": 2, "revocation_votes": 2,
    }
    assert events[7]["actor_id"] == "validator-c"


def test_audit_filters_and_limit(client, validators, trusted_alpha):
    v = bearer(validators["validator-a"])
    only_endorsements = client.get("/audit", params={"event_type": "agent_endorsed"}, headers=v).json()
    assert len(only_endorsements) == 2
    assert len(client.get("/audit", params={"limit": 1}, headers=v).json()) == 1
    assert client.get("/audit", params={"limit": 0}, headers=v).status_code == 422


def test_operator_endpoints_reject_agents_and_anonymous(client, validators, trusted_alpha):
    for path in ("/audit", "/graph"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers=bearer(trusted_alpha["token"])).status_code == 401


def test_admin_token_can_read_operator_endpoints(client, validators, monkeypatch):
    monkeypatch.setattr(config, "ADMIN_TOKEN", "admin-secret")
    assert client.get("/audit", headers=bearer("admin-secret")).status_code == 200
    assert client.get("/audit", headers=bearer("admin-wrong")).status_code == 401


# --- Graph endpoint ------------------------------------------------------------

def test_graph_shows_nodes_edges_and_live_status(client, validators, trusted_alpha, db):
    beta = register(client, "beta", parent_id=trusted_alpha["id"], token=trusted_alpha["token"])
    revoke(client, trusted_alpha["id"], validators["validator-c"], reason="suspicious")
    db.get(Validator, "validator-b").active = False  # B's endorsement should show counts=False
    db.commit()

    g = client.get("/graph", headers=bearer(validators["validator-a"])).json()
    nodes = {n["id"]: n for n in g["nodes"]}
    assert {n["type"] for n in g["nodes"]} == {"agent", "validator"}
    assert nodes["validator-b"]["active"] is False
    # Live decision: B inactive -> alpha drops to 1/2 endorsements -> pending.
    assert nodes[trusted_alpha["id"]]["status"] == "pending"
    assert nodes[beta["id"]]["status"] == "pending"

    edges = {(e["source"], e["target"], e["type"]): e for e in g["edges"]}
    assert edges[("validator-a", trusted_alpha["id"], "endorsement")]["counts"] is True
    assert edges[("validator-b", trusted_alpha["id"], "endorsement")]["counts"] is False
    assert edges[("validator-c", trusted_alpha["id"], "revocation_vote")]["reason"] == "suspicious"
    assert (trusted_alpha["id"], beta["id"], "lineage") in edges
    assert len(g["edges"]) == 4


# --- Concurrency ---------------------------------------------------------------

@pytest.fixture
def file_client(tmp_path):
    """File-backed SQLite so concurrent requests use separate connections and real locking."""
    app = create_app(f"sqlite:///{tmp_path / 'qg.db'}")
    with app.state.sessionmaker() as s:
        tokens = seed_validators(s)
        s.commit()
    with TestClient(app) as c:
        yield c, tokens, app


@pytest.mark.parametrize("action", ["endorse", "revoke"])
def test_concurrent_votes_yield_exactly_one_transition(file_client, action):
    """All 3 validators vote at once (quorum = 2). Exactly one status transition
    must be recorded, and for revocation the vote arriving after the agent is
    already revoked must be refused. Repeated over several agents for more
    interleavings."""
    client, tokens, app = file_client
    fn = endorse if action == "endorse" else revoke
    expected_new = "trusted" if action == "endorse" else "revoked"
    expected_codes = [201, 201, 201] if action == "endorse" else [201, 201, 409]

    for i in range(10):
        agent = register(client, f"contested-{i}")
        if action == "revoke":
            endorse(client, agent["id"], tokens["validator-a"])
            endorse(client, agent["id"], tokens["validator-b"])

        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda t: fn(client, agent["id"], t), tokens.values()))
        assert sorted(r.status_code for r in results) == expected_codes, [r.text for r in results]

        with app.state.sessionmaker() as s:
            transitions = s.scalars(
                select(AuditEvent).where(
                    AuditEvent.agent_id == agent["id"], AuditEvent.event_type == "agent_status_changed"
                )
            ).all()
        assert [t.details["new"] for t in transitions].count(expected_new) == 1, [t.details for t in transitions]
