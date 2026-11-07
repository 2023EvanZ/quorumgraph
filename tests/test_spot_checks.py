"""Spot checks: service-chosen, independent evidence that feeds revocation."""

import random

from fastapi.testclient import TestClient

from quorumgraph.main import create_app
from quorumgraph.seed import seed_validators

from .conftest import access, bearer, endorse, register, revoke

ADMIN = {"Authorization": "Bearer admin-secret"}


def _setup(seed=0):
    app = create_app("sqlite://", admin_token="admin-secret", spot_check_rng=random.Random(seed))
    with app.state.sessionmaker() as s:
        tokens = seed_validators(s)
        s.commit()
    return TestClient(app), tokens


def _trusted(client, tokens, name, by=("validator-a", "validator-b")):
    a = register(client, name)
    for v in by:
        endorse(client, a["id"], tokens[v])
    return a


def _sample(client, rate=1.0):
    r = client.post("/spot-checks/sample", json={"rate": rate}, headers=ADMIN)
    assert r.status_code == 201, r.text
    return r.json()


def _result(client, check, tokens, passed, who=None):
    return client.post(f"/spot-checks/{check['id']}/result", json={"passed": passed, "notes": "x"},
                       headers=bearer(tokens[who or check["validator_id"]]))


def test_only_admin_can_draw_a_sample():
    client, tokens = _setup()
    assert client.post("/spot-checks/sample", json={"rate": 1}).status_code == 401
    assert client.post("/spot-checks/sample", json={"rate": 1},
                       headers=bearer(tokens["validator-a"])).status_code == 401
    assert client.post("/spot-checks/sample", json={"rate": 0}, headers=ADMIN).status_code == 422


def test_sample_covers_trusted_agents_only_and_auditor_is_independent():
    client, tokens = _setup()
    t = _trusted(client, tokens, "trusted")
    register(client, "pending")
    checks = _sample(client)
    assert [c["agent_id"] for c in checks] == [t["id"]]
    assert checks[0]["validator_id"] == "validator-c"  # a and b vouched for it, so they can't check it


def test_agent_endorsed_by_everyone_is_skipped_and_that_is_recorded():
    client, tokens = _setup()
    a = _trusted(client, tokens, "all", by=("validator-a", "validator-b", "validator-c"))
    assert _sample(client) == []
    events = client.get("/audit", params={"agent_id": a["id"], "event_type": "spot_check_assigned"},
                        headers=ADMIN).json()
    assert events[0]["details"]["skipped"] == "no independent validator"


def test_sampling_rate_is_respected_roughly():
    client, tokens = _setup(seed=1)
    for i in range(60):
        _trusted(client, tokens, f"a{i}")
    n = len(_sample(client, rate=0.25))
    assert 5 <= n <= 25


def test_only_the_assigned_validator_resolves_once():
    client, tokens = _setup()
    _trusted(client, tokens, "t")
    (check,) = _sample(client)
    assert _result(client, check, tokens, True, who="validator-a").status_code == 403
    assert _result(client, check, tokens, True).status_code == 200
    assert _result(client, check, tokens, True).status_code == 409


def test_pass_casts_no_vote():
    client, tokens = _setup()
    t = _trusted(client, tokens, "t")
    (check,) = _sample(client)
    r = _result(client, check, tokens, True)
    assert r.json()["result"] == "passed" and r.json()["agent_status"] == "trusted"
    assert client.get(f"/agents/{t['id']}").json()["revocation_votes"] == 0


def test_failure_is_one_vote_and_quorum_still_decides():
    client, tokens = _setup()
    t = _trusted(client, tokens, "t")
    (check,) = _sample(client)
    r = _result(client, check, tokens, False)
    assert r.json()["result"] == "failed" and r.json()["agent_status"] == "trusted"  # 1 of 2 votes
    assert access(client, t["token"]).status_code == 200
    assert revoke(client, t["id"], tokens["validator-a"]).json()["agent_status"] == "revoked"
    assert access(client, t["token"]).status_code == 403


def test_failure_on_an_already_revoked_agent_is_still_recorded():
    client, tokens = _setup()
    t = _trusted(client, tokens, "t")
    (check,) = _sample(client)
    revoke(client, t["id"], tokens["validator-a"])
    revoke(client, t["id"], tokens["validator-b"])
    r = _result(client, check, tokens, False)
    assert r.status_code == 200 and r.json()["result"] == "failed" and r.json()["agent_status"] == "revoked"


def test_failure_after_auditor_already_voted_keeps_the_record():
    client, tokens = _setup()
    t = _trusted(client, tokens, "t")
    (check,) = _sample(client)
    revoke(client, t["id"], tokens["validator-c"])  # the auditor already voted
    r = _result(client, check, tokens, False)
    assert r.status_code == 200 and r.json()["result"] == "failed"
    assert client.get(f"/agents/{t['id']}").json()["revocation_votes"] == 1


def test_operator_can_list_open_checks():
    client, tokens = _setup()
    _trusted(client, tokens, "t1")
    _trusted(client, tokens, "t2")
    checks = _sample(client)
    _result(client, checks[0], tokens, True)
    open_checks = client.get("/spot-checks", params={"open_only": True}, headers=ADMIN).json()
    assert [c["id"] for c in open_checks] == [checks[1]["id"]]
    assert client.get("/spot-checks").status_code == 401


def test_promoted_validator_never_audits_its_own_lineage():
    app = create_app("sqlite://", admin_token="admin-secret", spot_check_rng=random.Random(0))
    with app.state.sessionmaker() as s:
        tokens = seed_validators(s)
        s.commit()
    client = TestClient(app)
    parent = _trusted(client, tokens, "parent")
    v = client.post("/validators", json={"agent_id": parent["id"], "name": "p"}, headers=ADMIN).json()
    child = register(client, "child", parent["id"], parent["token"])
    endorse(client, child["id"], tokens["validator-a"])
    endorse(client, child["id"], tokens["validator-b"])
    for _ in range(20):  # c and the promoted parent are both non-endorsers; only c may check the child
        for c in _sample(client):
            if c["agent_id"] == child["id"]:
                assert c["validator_id"] != v["id"]
