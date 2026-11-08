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


def test_include_pending_samples_unendorsed_agents_but_never_revoked_ones():
    client, tokens = _setup()
    t = _trusted(client, tokens, "trusted")
    p = register(client, "pending")
    gone = register(client, "gone")
    revoke(client, gone["id"], tokens["validator-a"])
    revoke(client, gone["id"], tokens["validator-b"])
    r = client.post("/spot-checks/sample", json={"rate": 1, "include_pending": True}, headers=ADMIN)
    assert sorted(c["agent_id"] for c in r.json()) == sorted([t["id"], p["id"]])


def test_skipped_count_is_reported_in_a_header():
    client, tokens = _setup()
    _trusted(client, tokens, "all", by=("validator-a", "validator-b", "validator-c"))
    _trusted(client, tokens, "two")
    r = client.post("/spot-checks/sample", json={"rate": 1}, headers=ADMIN)
    assert len(r.json()) == 1 and r.headers["X-Spot-Checks-Skipped"] == "1"


def test_agent_ids_restricts_the_frame():
    client, tokens = _setup()
    a = _trusted(client, tokens, "a")
    _trusted(client, tokens, "b")
    r = client.post("/spot-checks/sample", json={"rate": 1, "agent_ids": [a["id"]]}, headers=ADMIN)
    assert [c["agent_id"] for c in r.json()] == [a["id"]]


def test_failure_escalates_to_a_second_validator_and_confirmation_revokes():
    client, tokens = _setup()
    a = _trusted(client, tokens, "a")
    (check,) = _sample(client)
    r = _result(client, check, tokens, passed=False).json()
    assert r["agent_status"] == "trusted"  # one vote: not revoked yet
    conf = r["confirmation"]
    assert conf and conf["confirms_id"] == check["id"] and conf["validator_id"] != check["validator_id"]
    # confirmers may be endorsers (a or b here): confirming a failure is against their interest
    assert conf["validator_id"] in ("validator-a", "validator-b")
    assert _result(client, conf, tokens, passed=False, who="validator-c").status_code == 403  # not assigned
    r2 = _result(client, conf, tokens, passed=False).json()
    assert r2["agent_status"] == "revoked" and r2["confirmation"] is None
    assert access(client, a["token"]).status_code == 403


def test_disputed_confirmation_casts_no_vote_and_never_escalates_again():
    client, tokens = _setup()
    _trusted(client, tokens, "a")
    (check,) = _sample(client)
    conf = _result(client, check, tokens, passed=False).json()["confirmation"]
    r = _result(client, conf, tokens, passed=True).json()
    assert r["agent_status"] == "trusted" and r["confirmation"] is None
    # and a failed confirmation can't spawn a third check either
    client2, tokens2 = _setup(seed=1)
    _trusted(client2, tokens2, "b")
    (c1,) = _sample(client2)
    c2 = _result(client2, c1, tokens2, passed=False).json()["confirmation"]
    assert _result(client2, c2, tokens2, passed=False).json()["confirmation"] is None


def test_escalation_can_be_disabled():
    app = create_app("sqlite://", admin_token="admin-secret", spot_check_rng=random.Random(0),
                     spot_check_escalation=False)
    with app.state.sessionmaker() as s:
        tokens = seed_validators(s)
        s.commit()
    client = TestClient(app)
    _trusted(client, tokens, "a")
    (check,) = _sample(client)
    r = _result(client, check, tokens, passed=False).json()
    assert r["confirmation"] is None and r["agent_status"] == "trusted"


def test_validator_promoted_from_a_descendant_never_audits_or_confirms_the_ancestor():
    auditors, confirmers = set(), set()
    for seed in range(12):
        client, tokens = _setup(seed)
        parent = _trusted(client, tokens, "parent")
        child = register(client, "child", parent["id"], parent["token"])
        endorse(client, child["id"], tokens["validator-a"])
        endorse(client, child["id"], tokens["validator-b"])
        client.post("/validators", json={"agent_id": child["id"], "name": "child-v"}, headers=ADMIN)
        checks = client.post("/spot-checks/sample", json={"rate": 1, "agent_ids": [parent["id"]]},
                             headers=ADMIN).json()
        (c,) = checks
        auditors.add(c["validator_id"])
        conf = _result(client, c, tokens, passed=False).json()["confirmation"]
        confirmers.add(conf["validator_id"])
    # child-v is a non-endorser of parent, so only kinship can exclude it
    assert auditors == {"validator-c"}
    assert confirmers <= {"validator-a", "validator-b"} and len(confirmers) == 2


def test_inclusion_probs_keep_the_uniform_budget_and_cap_at_one():
    from quorumgraph.routers.spot_checks import _inclusion_probs
    assert _inclusion_probs(0.25, [1.0] * 8) == [0.25] * 8  # equal weights = uniform
    p = _inclusion_probs(0.25, [3.0, 1.0, 1.0, 1.0, 1.0, 1.0])
    assert abs(sum(p) - 0.25 * 6) < 1e-9 and p[0] == 3 * p[1]
    p = _inclusion_probs(0.5, [100.0, 1.0, 1.0, 1.0])  # the heavy one is capped, excess spread
    assert p[0] == 1.0 and abs(sum(p) - 2.0) < 1e-9 and abs(p[1] - 1 / 3) < 1e-9


def test_lineage_weighting_checks_successors_of_flagged_agents_more_often():
    client, tokens = _setup(seed=4)
    parent = _trusted(client, tokens, "parent")
    child = register(client, "child", parent["id"], parent["token"])
    endorse(client, child["id"], tokens["validator-a"])
    endorse(client, child["id"], tokens["validator-b"])
    others = [_trusted(client, tokens, f"o{i}")["id"] for i in range(9)]
    (c,) = client.post("/spot-checks/sample", json={"rate": 1, "agent_ids": [parent["id"]]}, headers=ADMIN).json()
    assert _result(client, c, tokens, passed=False).json()["agent_status"] == "trusted"  # 1 fail + 1 vote
    frame = [child["id"], *others]

    def counts(weighting):
        n = dict.fromkeys(frame, 0)
        for _ in range(300):
            r = client.post("/spot-checks/sample", json={"rate": 0.1, "agent_ids": frame, "weighting": weighting},
                            headers=ADMIN)
            for chk in r.json():
                n[chk["agent_id"]] += 1
        return n

    lin, uni = counts("lineage"), counts("uniform")
    mean_other = lambda n: sum(n[o] for o in others) / len(others)
    # weights: child 1 + (1 fail + 1 vote) = 3, others 1 → p = 0.25 vs 0.083; uniform 0.1 each
    assert lin[child["id"]] > 2 * mean_other(lin)
    assert uni[child["id"]] < 2 * mean_other(uni)
    assert abs(sum(lin.values()) - sum(uni.values())) < 0.25 * sum(uni.values())  # same budget


# --- per-action spot checks (gateway-time sampling) ------------------------------

def _setup_action(rate, seed=0):
    app = create_app("sqlite://", admin_token="admin-secret", spot_check_rng=random.Random(seed),
                     action_audit_rate=rate)
    with app.state.sessionmaker() as s:
        tokens = seed_validators(s)
        s.commit()
    return TestClient(app), tokens


def _open_checks(client, agent_id):
    return client.get("/spot-checks", params={"agent_id": agent_id, "open_only": True}, headers=ADMIN).json()


def test_action_checks_are_off_by_default():
    client, tokens = _setup()
    a = _trusted(client, tokens, "t")
    for _ in range(20):
        assert access(client, a["token"]).status_code == 200
    assert _open_checks(client, a["id"]) == []


def test_each_allowed_action_can_be_checked_and_the_check_names_that_action():
    client, tokens = _setup_action(1.0)
    a = _trusted(client, tokens, "t")
    r = access(client, a["token"])
    assert r.status_code == 200
    (check,) = _open_checks(client, a["id"])
    assert check["validator_id"] == "validator-c"  # a and b endorsed it
    assert check["action_event_id"] is not None
    events = client.get("/audit", params={"agent_id": a["id"], "event_type": "access_allowed"}, headers=ADMIN).json()
    assert check["action_event_id"] in {e["id"] for e in events}


def test_agent_cannot_tell_whether_its_action_is_checked():
    on, t_on = _setup_action(1.0)
    off, t_off = _setup_action(0.0)
    r_on = access(on, _trusted(on, t_on, "t")["token"])
    r_off = access(off, _trusted(off, t_off, "t")["token"])
    assert r_on.status_code == r_off.status_code == 200
    assert set(r_on.json()) == set(r_off.json())
    assert r_on.json()["document"] == r_off.json()["document"]
    assert {k for k in r_on.headers if "spot" in k.lower()} == set()


def test_denied_access_opens_no_check():
    client, tokens = _setup_action(1.0)
    p = register(client, "pending")
    assert access(client, p["token"]).status_code == 403
    assert _open_checks(client, p["id"]) == []


def test_action_check_rate_is_respected_roughly():
    client, tokens = _setup_action(0.25, seed=3)
    a = _trusted(client, tokens, "t")
    for _ in range(80):
        access(client, a["token"])
    n = len(_open_checks(client, a["id"]))
    assert 8 <= n <= 35


def test_failed_action_check_escalates_on_the_same_action_and_revokes_mid_stream():
    client, tokens = _setup_action(1.0)
    a = _trusted(client, tokens, "t")
    access(client, a["token"])
    (check,) = _open_checks(client, a["id"])
    res = _result(client, check, tokens, False).json()
    conf = res["confirmation"]
    assert conf["action_event_id"] == check["action_event_id"]
    assert conf["validator_id"] != check["validator_id"]
    res2 = _result(client, conf, tokens, False).json()
    assert res2["agent_status"] == "revoked"
    assert access(client, a["token"]).status_code == 403  # the rest of its actions are cut off


def test_action_with_no_independent_auditor_is_skipped_and_recorded():
    client, tokens = _setup_action(1.0)
    a = _trusted(client, tokens, "all", by=("validator-a", "validator-b", "validator-c"))
    assert access(client, a["token"]).status_code == 200
    assert _open_checks(client, a["id"]) == []
    (ev,) = client.get("/audit", params={"agent_id": a["id"], "event_type": "spot_check_assigned"},
                       headers=ADMIN).json()
    assert ev["details"]["skipped"] == "no independent validator"
    assert ev["details"]["action_event_id"] is not None


def test_action_audit_rate_is_validated():
    import pytest
    with pytest.raises(ValueError):
        create_app("sqlite://", action_audit_rate=1.5)


def test_basic_tier_admits_pending_agents_is_action_audited_and_shuts_revoked_ones_out():
    client, tokens = _setup_action(1.0)
    p = register(client, "pending")
    r = client.get("/protected/basic", headers=bearer(p["token"]))
    assert r.status_code == 200
    (check,) = _open_checks(client, p["id"])
    conf = _result(client, check, tokens, False).json()["confirmation"]
    assert _result(client, conf, tokens, False).json()["agent_status"] == "revoked"
    assert client.get("/protected/basic", headers=bearer(p["token"])).status_code == 403
