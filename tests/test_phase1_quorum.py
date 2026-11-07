"""Phase 1: registration, authenticated endorsements, quorum-gated access, clone isolation."""

import hashlib

from sqlalchemy import select

from quorumgraph import config
from quorumgraph.models import Agent, AuditEvent, Validator

from .conftest import access, bearer, endorse, register


# --- Quorum enforcement --------------------------------------------------------

def test_new_agent_is_pending_and_denied(client, validators):
    alpha = register(client, "alpha")
    assert alpha["status"] == "pending"

    resp = access(client, alpha["token"])
    assert resp.status_code == 403
    assert "0/2" in resp.json()["detail"]


def test_one_endorsement_is_not_enough(client, validators):
    alpha = register(client, "alpha")
    resp = endorse(client, alpha["id"], validators["validator-a"])
    assert resp.status_code == 201
    assert resp.json()["agent_status"] == "pending"

    assert access(client, alpha["token"]).status_code == 403


def test_two_distinct_endorsements_grant_access(client, validators):
    alpha = register(client, "alpha")
    endorse(client, alpha["id"], validators["validator-a"])
    resp = endorse(client, alpha["id"], validators["validator-b"])
    assert resp.json()["agent_status"] == "trusted"

    resp = access(client, alpha["token"])
    assert resp.status_code == 200
    assert resp.json()["agent_id"] == alpha["id"]

    info = client.get(f"/agents/{alpha['id']}").json()
    assert info["status"] == "trusted"
    assert info["endorsed_by"] == ["validator-a", "validator-b"]


def test_quorum_threshold_is_configurable(client, validators, monkeypatch):
    monkeypatch.setattr(config, "ENDORSEMENT_QUORUM", 3)
    alpha = register(client, "alpha")
    endorse(client, alpha["id"], validators["validator-a"])
    endorse(client, alpha["id"], validators["validator-b"])
    assert access(client, alpha["token"]).status_code == 403
    endorse(client, alpha["id"], validators["validator-c"])
    assert access(client, alpha["token"]).status_code == 200


# --- Duplicate votes -----------------------------------------------------------

def test_duplicate_endorsement_rejected_and_not_double_counted(client, validators):
    alpha = register(client, "alpha")
    assert endorse(client, alpha["id"], validators["validator-a"]).status_code == 201
    resp = endorse(client, alpha["id"], validators["validator-a"])
    assert resp.status_code == 409

    assert client.get(f"/agents/{alpha['id']}").json()["endorsements"] == 1
    assert access(client, alpha["token"]).status_code == 403


# --- Authentication boundaries -------------------------------------------------

def test_agent_cannot_endorse_itself(client, validators):
    """Agent tokens are not validator credentials, so self-endorsement is impossible."""
    alpha = register(client, "alpha")
    resp = endorse(client, alpha["id"], alpha["token"])
    assert resp.status_code == 401
    assert client.get(f"/agents/{alpha['id']}").json()["endorsements"] == 0


def test_validator_token_cannot_access_protected_resource(client, validators):
    assert access(client, validators["validator-a"]).status_code == 401


def test_missing_or_invalid_agent_token_is_401(client, validators):
    assert client.get("/protected/resource").status_code == 401
    resp = access(client, "qga_not-a-real-token")
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"


def test_endorse_requires_validator_auth(client, validators):
    alpha = register(client, "alpha")
    assert client.post(f"/agents/{alpha['id']}/endorse").status_code == 401
    assert endorse(client, alpha["id"], "qgv_forged").status_code == 401


def test_inactive_validator_cannot_endorse_and_old_edges_stop_counting(client, validators, db):
    alpha = register(client, "alpha")
    endorse(client, alpha["id"], validators["validator-a"])
    endorse(client, alpha["id"], validators["validator-b"])
    assert access(client, alpha["token"]).status_code == 200

    db.get(Validator, "validator-b").active = False
    db.commit()

    assert endorse(client, alpha["id"], validators["validator-b"]).status_code == 401
    # B's existing endorsement no longer counts, so Alpha drops below quorum.
    assert access(client, alpha["token"]).status_code == 403


def test_endorse_unknown_agent_is_404(client, validators):
    assert endorse(client, "does-not-exist", validators["validator-a"]).status_code == 404


# --- Clone isolation -----------------------------------------------------------

def test_clone_does_not_inherit_authority(client, validators):
    alpha = register(client, "alpha")
    endorse(client, alpha["id"], validators["validator-a"])
    endorse(client, alpha["id"], validators["validator-b"])
    assert access(client, alpha["token"]).status_code == 200

    beta = register(client, "beta", parent_id=alpha["id"], token=alpha["token"])
    assert beta["parent_agent_id"] == alpha["id"]
    assert beta["status"] == "pending"
    assert beta["token"] != alpha["token"]
    assert access(client, beta["token"]).status_code == 403
    # Parent unaffected.
    assert access(client, alpha["token"]).status_code == 200


def test_child_registration_requires_parent_credential(client, validators):
    alpha = register(client, "alpha")
    mallory = register(client, "mallory")

    no_auth = client.post("/agents", json={"name": "fake-child", "parent_agent_id": alpha["id"]})
    assert no_auth.status_code == 401

    forged = client.post(
        "/agents", json={"name": "fake-child", "parent_agent_id": alpha["id"]}, headers=bearer(mallory["token"])
    )
    assert forged.status_code == 403


# --- Storage and audit ---------------------------------------------------------

def test_tokens_are_stored_only_as_hashes(client, validators, db):
    alpha = register(client, "alpha")
    row = db.get(Agent, alpha["id"])
    assert row.token_hash != alpha["token"]
    assert row.token_hash == hashlib.sha256(alpha["token"].encode()).hexdigest()


def test_audit_log_records_full_history(client, validators, db):
    alpha = register(client, "alpha")
    access(client, alpha["token"])
    endorse(client, alpha["id"], validators["validator-a"])
    endorse(client, alpha["id"], validators["validator-b"])
    access(client, alpha["token"])

    events = db.scalars(
        select(AuditEvent).where(AuditEvent.agent_id == alpha["id"]).order_by(AuditEvent.id)
    ).all()
    assert [e.event_type for e in events] == [
        "agent_registered",
        "access_denied",
        "agent_endorsed",
        "agent_endorsed",
        "agent_status_changed",
        "access_allowed",
    ]
    transition = events[4]
    assert transition.details["old"] == "pending" and transition.details["new"] == "trusted"
    assert transition.actor_id == "validator-b"
