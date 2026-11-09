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


def _kin_chain(client, tokens):
    """grandparent -> parent (both trusted and promoted) -> child (pending)."""
    gp = _trusted(client, tokens, "gp")
    p = _trusted(client, tokens, "p", parent=gp)
    v_gp, v_p = _promote(client, gp), _promote(client, p)
    child = register(client, "child", p["id"], p["token"])
    return v_gp, v_p, child


def test_soft_guard_accepts_kin_endorsements_but_kin_alone_cannot_trust():
    _, client, tokens = _setup(lineage_guard="soft")
    v_gp, v_p, child = _kin_chain(client, tokens)
    assert endorse(client, child["id"], v_gp["token"]).status_code == 201  # accepted, not blocked
    r = endorse(client, child["id"], v_p["token"])
    assert r.status_code == 201
    assert r.json()["endorsements"] == 2 and r.json()["agent_status"] == "pending"
    assert access(client, child["token"]).status_code == 403  # the gateway applies the same rule
    assert client.get(f"/agents/{child['id']}").json()["status"] == "pending"
    r = endorse(client, child["id"], tokens["validator-c"])  # one independent endorser completes it
    assert r.json()["agent_status"] == "trusted"
    assert access(client, child["token"]).status_code == 200


def test_soft_guard_one_kin_plus_one_independent_is_enough():
    _, client, tokens = _setup(lineage_guard="soft")
    v_gp, _, child = _kin_chain(client, tokens)
    endorse(client, child["id"], v_gp["token"])
    assert endorse(client, child["id"], tokens["validator-a"]).json()["agent_status"] == "trusted"


def test_soft_guard_unrelated_promoted_validators_are_independent():
    _, client, tokens = _setup(lineage_guard="soft")
    v1 = _promote(client, _trusted(client, tokens, "o1"))
    v2 = _promote(client, _trusted(client, tokens, "o2"))
    x = register(client, "x")
    endorse(client, x["id"], v1["token"])
    assert endorse(client, x["id"], v2["token"]).json()["agent_status"] == "trusted"


def test_soft_guard_trust_lapses_if_the_independent_endorser_is_deactivated():
    _, client, tokens = _setup(lineage_guard="soft")
    v_gp, v_p, child = _kin_chain(client, tokens)
    v_other = _promote(client, _trusted(client, tokens, "other"))
    for v in (v_gp, v_p, v_other):
        endorse(client, child["id"], v["token"])
    assert access(client, child["token"]).status_code == 200
    client.post(f"/validators/{v_other['id']}/deactivate", headers=ADMIN)
    assert access(client, child["token"]).status_code == 403  # 2 active endorsements, both kin


def test_guard_mode_parsing():
    import pytest
    from quorumgraph.config import parse_lineage_guard
    assert [parse_lineage_guard(v) for v in (True, False, "1", "0", "soft", "block", "off")] == \
        ["block", "off", "block", "off", "soft", "block", "off"]
    with pytest.raises(ValueError):
        parse_lineage_guard("maybe")


def test_graph_links_promoted_validators_to_their_agent_and_agent_view_explains_soft_guard():
    _, client, tokens = _setup(lineage_guard="soft")
    v_gp, v_p, child = _kin_chain(client, tokens)
    nodes = {n["id"]: n for n in client.get("/graph", headers=ADMIN).json()["nodes"]}
    assert nodes[v_gp["id"]]["agent_id"] == v_gp["agent_id"]
    assert nodes["validator-a"]["agent_id"] is None
    endorse(client, child["id"], v_gp["token"])
    endorse(client, child["id"], v_p["token"])
    d = client.get(f"/agents/{child['id']}").json()
    assert d["status"] == "pending" and d["needs_independent"] is True
    assert client.get("/operator/me", headers=ADMIN).json()["lineage_guard"] == "soft"


def test_block_guard_also_refuses_a_descendant_endorsing_its_ancestor():
    _, client, tokens = _setup()
    parent = _trusted(client, tokens, "parent")
    child = _trusted(client, tokens, "child", parent=parent)
    v = _promote(client, child)
    sibling = register(client, "sibling", parent["id"], parent["token"])
    assert endorse(client, parent["id"], v["token"]).status_code == 403  # child's validator → its own parent
    assert endorse(client, sibling["id"], v["token"]).status_code == 201  # siblings are not kin (direct line only)


def test_soft_guard_descendant_validators_are_not_independent():
    _, client, tokens = _setup(lineage_guard="soft")
    root = register(client, "root")
    child = register(client, "child", root["id"], root["token"])
    endorse(client, child["id"], tokens["validator-a"])
    endorse(client, child["id"], tokens["validator-b"])
    v = _promote(client, child)
    endorse(client, root["id"], v["token"])
    v2 = _promote(client, _trusted(client, tokens, "grandchild", parent=child))
    r = endorse(client, root["id"], v2["token"])
    assert r.json()["agent_status"] == "pending"  # two descendant validators: kin-only quorum
    assert client.get(f"/agents/{root['id']}").json()["needs_independent"] is True
    r = endorse(client, root["id"], tokens["validator-a"])
    assert r.json()["agent_status"] == "trusted"  # one independent seeded endorser


# --- kin radius: collateral relatives ---------------------------------------------

def _setup_radius(guard, radius):
    app = create_app("sqlite://", admin_token="admin-secret", lineage_guard=guard, kin_radius=radius)
    with app.state.sessionmaker() as s:
        tokens = seed_validators(s)
        s.commit()
    return app, TestClient(app), tokens


def _family(client, tokens):
    """root → (a, b) siblings; a → a1; b → b1 (a1 and b1 are first cousins)."""
    root = _trusted(client, tokens, "root")
    a = _trusted(client, tokens, "a", parent=root)
    b = _trusted(client, tokens, "b", parent=root)
    a1 = _trusted(client, tokens, "a1", parent=a)
    b1 = register(client, "b1", b["id"], b["token"])
    return root, a, b, a1, b1


def test_kin_radius_default_is_direct_line_only():
    app, client, tokens = _setup_radius("block", None)
    assert app.state.kin_radius == 0
    _, a, b, a1, b1 = _family(client, tokens)
    v_a1 = _promote(client, a1)
    assert endorse(client, b1["id"], v_a1["token"]).status_code == 201  # cousin is not kin at radius 0


def test_kin_radius_one_covers_siblings_not_cousins():
    _, client, tokens = _setup_radius("block", 1)
    _, a, b, a1, b1 = _family(client, tokens)
    v_a = _promote(client, a)
    assert endorse(client, b["id"], v_a["token"]).status_code == 403   # sibling
    v_a1 = _promote(client, a1)
    assert endorse(client, b1["id"], v_a1["token"]).status_code == 201  # cousin: common ancestor 2 back


def test_kin_radius_two_covers_cousins_and_uncles():
    _, client, tokens = _setup_radius("block", 2)
    root, a, b, a1, b1 = _family(client, tokens)
    v_a1 = _promote(client, a1)
    assert endorse(client, b1["id"], v_a1["token"]).status_code == 403  # first cousin
    v_a = _promote(client, a)
    assert endorse(client, b1["id"], v_a["token"]).status_code == 403   # uncle → nephew
    stranger = register(client, "stranger")
    assert endorse(client, stranger["id"], v_a["token"]).status_code == 201  # different root


def test_soft_guard_cousins_count_as_independent_only_at_radius_zero():
    for radius, expected in ((0, "trusted"), (2, "pending")):
        _, client, tokens = _setup_radius("soft", radius)
        _, a, b, a1, b1 = _family(client, tokens)
        v_a1 = _promote(client, a1)
        v_b = _promote(client, b)  # b1's parent: always kin
        endorse(client, b1["id"], v_b["token"])
        r = endorse(client, b1["id"], v_a1["token"])
        assert r.json()["agent_status"] == expected, radius


def test_kin_radius_affects_auditor_independence():
    from quorumgraph import trust
    from quorumgraph.models import Agent as DBAgent, Validator
    app, client, tokens = _setup_radius("soft", 2)
    _, a, b, a1, b1 = _family(client, tokens)
    v_a1 = _promote(client, a1)
    with app.state.sessionmaker() as s:
        vid = s.get(Validator, v_a1["id"]).agent_id
        assert trust.is_kin(s, validator_agent_id=vid, agent=s.get(DBAgent, b1["id"]))


def test_kin_radius_validated_and_reported():
    import pytest
    from quorumgraph.config import parse_kin_radius
    assert parse_kin_radius("3") == 3
    with pytest.raises(ValueError):
        parse_kin_radius(-1)
    _, client, _ = _setup_radius("soft", 2)
    assert client.get("/operator/me", headers=ADMIN).json()["kin_radius"] == 2
