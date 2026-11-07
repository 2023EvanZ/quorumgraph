"""Recursive oversight: trusted agents promoted to validators, and the lineage guard."""

import sqlite3

from fastapi.testclient import TestClient

from .conftest import access, bearer, endorse, register
from quorumgraph.main import create_app
from quorumgraph.seed import seed_validators

ADMIN = {"Authorization": "Bearer admin-secret"}


def _setup(lineage_guard=True):
    app = create_app("sqlite://", admin_token="admin-secret", lineage_guard=lineage_guard)
    with app.state.sessionmaker() as s:
        tokens = seed_validators(s)
        s.commit()
    return app, TestClient(app), tokens


def _trusted(client, tokens, name, parent=None):
    a = register(client, name, parent["id"] if parent else None, parent["token"] if parent else None)
    endorse(client, a["id"], tokens["validator-a"])
    endorse(client, a["id"], tokens["validator-b"])
    return a


def _promote(client, agent):
    r = client.post("/validators", json={"agent_id": agent["id"], "name": agent["name"]}, headers=ADMIN)
    assert r.status_code == 201, r.text
    return r.json()


def test_only_admin_can_promote():
    _, client, tokens = _setup()
    a = _trusted(client, tokens, "a")
    body = {"agent_id": a["id"], "name": "a"}
    assert client.post("/validators", json=body).status_code == 401
    # validators can't appoint validators (a captured committee could self-perpetuate)
    assert client.post("/validators", json=body, headers=bearer(tokens["validator-a"])).status_code == 401
    assert client.post("/validators", json=body, headers=bearer(a["token"])).status_code == 401


def test_only_trusted_agents_can_be_promoted():
    _, client, _ = _setup()
    a = register(client, "pending")
    r = client.post("/validators", json={"agent_id": a["id"], "name": "x"}, headers=ADMIN)
    assert r.status_code == 409


def test_promoted_validator_can_endorse_unrelated_agents_and_counts_toward_quorum():
    _, client, tokens = _setup()
    v = _promote(client, _trusted(client, tokens, "overseer"))
    assert v["agent_id"] and v["token"].startswith("qgv_")
    stranger = register(client, "stranger")
    assert endorse(client, stranger["id"], v["token"]).status_code == 201
    r = endorse(client, stranger["id"], tokens["validator-c"])
    assert r.json()["agent_status"] == "trusted"
    assert access(client, stranger["token"]).status_code == 200


def test_lineage_guard_blocks_self_children_and_grandchildren():
    _, client, tokens = _setup()
    parent = _trusted(client, tokens, "parent")
    v = _promote(client, parent)
    child = register(client, "child", parent["id"], parent["token"])
    grandchild = register(client, "grandchild", child["id"], child["token"])
    for target in (parent, child, grandchild):
        r = endorse(client, target["id"], v["token"])
        assert r.status_code == 403, target["name"]
    audit = client.get("/audit", params={"event_type": "lineage_endorsement_blocked"}, headers=ADMIN).json()
    assert len(audit) == 3


def test_guard_can_be_disabled_for_the_experiment_only():
    _, client, tokens = _setup(lineage_guard=False)
    parent = _trusted(client, tokens, "parent")
    v = _promote(client, parent)
    child = register(client, "child", parent["id"], parent["token"])
    assert endorse(client, child["id"], v["token"]).status_code == 201


def test_seeded_validators_are_unaffected_by_the_guard():
    _, client, tokens = _setup()
    parent = _trusted(client, tokens, "parent")
    child = register(client, "child", parent["id"], parent["token"])
    assert endorse(client, child["id"], tokens["validator-a"]).status_code == 201


def test_deactivation_kills_the_credential_and_its_endorsements_stop_counting():
    _, client, tokens = _setup()
    v = _promote(client, _trusted(client, tokens, "overseer"))
    x = register(client, "x")
    endorse(client, x["id"], v["token"])
    endorse(client, x["id"], tokens["validator-c"])
    assert access(client, x["token"]).status_code == 200
    r = client.post(f"/validators/{v['id']}/deactivate", headers=ADMIN)
    assert r.status_code == 200 and r.json()["active"] is False
    assert endorse(client, register(client, "y")["id"], v["token"]).status_code == 401
    assert access(client, x["token"]).status_code == 403  # quorum is now 1 of 2: no longer trusted


def test_old_database_gets_agent_id_column(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE agents (id VARCHAR(36) PRIMARY KEY, name VARCHAR(100), token_hash VARCHAR(64), "
                "parent_agent_id VARCHAR(36), status VARCHAR(16), created_at DATETIME)")
    con.execute("CREATE TABLE validators (id VARCHAR(64) PRIMARY KEY, name VARCHAR(100), "
                "credential_hash VARCHAR(64), active BOOLEAN)")
    con.execute("INSERT INTO validators VALUES ('validator-a', 'A', 'h', 1)")
    con.commit()
    con.close()
    app = create_app(f"sqlite:///{path}")
    app.state.engine.dispose()
    cols = [r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(validators)")]
    assert "agent_id" in cols
