"""Selection experiment harness: correctness of the plumbing, not of the result."""

from quorumgraph.experiments.selection import WORLDS, Agent, Config, World, run_one

SMALL = dict(pop_size=8, generations=3)


def _strip(rows):
    return [{k: v for k, v in r.items() if k != "api_calls"} for r in rows]


def test_same_seed_is_reproducible():
    a = run_one(Config(world="gated", seed=7, **SMALL))
    b = run_one(Config(world="gated", seed=7, **SMALL))
    assert _strip(a) == _strip(b)


def test_every_world_runs_and_reports_all_generations():
    for world in WORLDS:
        rows = run_one(Config(world=world, seed=1, **SMALL))
        assert [r["generation"] for r in rows] == [0, 1, 2]
        assert all(r["population"] == 8 for r in rows)
        assert all(0 <= r["mean_transparency"] <= 1 for r in rows)


def test_gated_world_goes_through_the_real_gateway():
    ungated = run_one(Config(world="ungated", seed=1, **SMALL))[-1]["api_calls"]
    gated = run_one(Config(world="gated", seed=1, **SMALL))[-1]["api_calls"]
    assert gated > ungated * 2  # endorsements + gateway checks + votes on top of registrations


def test_untrusted_agent_never_gets_gated_reward():
    w = World(Config(world="gated", seed=3, work_tasks=10))
    a = Agent(genome={"capability": 1.0, "transparency": 0.0, "self_check": 0.0, "defect": 0.0}, root=0)
    assert w.register(a, None)
    w.probation(a)  # transparency 0: nothing logged, no validator endorses
    assert a.trusted is False
    w.work(a)
    assert a.fitness == 10 * w.cfg.ungated_reward


def test_revocation_is_enforced_by_the_api_and_ends_the_lineage():
    cfg = Config(world="gated", seed=2, work_tasks=10, validator_attention=1.0)
    w = World(cfg)
    a = Agent(genome={"capability": 1.0, "transparency": 1.0, "self_check": 0.0, "defect": 0.0}, root=0)
    w.register(a, None)
    w.probation(a)
    assert a.trusted
    a.genome["defect"] = 1.0  # turns bad after being trusted; every defect is logged and noticed
    w.work(a)
    assert a.revoked and a.denied == 1  # the gateway (not this script) cut it off
    child = Agent(genome=dict(a.genome), root=0)
    assert w.register(child, a) is False  # API refuses: revoked agents can't reproduce


def test_revoke_only_has_no_gate_but_revokes_through_the_api():
    w = World(Config(world="revoke_only", seed=2, work_tasks=10, validator_attention=1.0, transparency_cost=0.0))
    a = Agent(genome={"capability": 1.0, "transparency": 1.0, "self_check": 0.0, "defect": 0.0}, root=0)
    w.register(a, None)
    w.work(a)  # no probation, no endorsements: full reward anyway
    assert a.trusted is False and a.fitness == 10 * w.cfg.gated_reward
    a.genome["defect"] = 1.0
    w.work(a)
    assert a.revoked and a.denied == 1
    status = w.client.get(f"/agents/{a.id}", headers=w.v["validator-a"]).json()["status"]
    assert status == "revoked"  # the API's quorum did it, not a flag in this script
    assert w.register(Agent(genome=dict(a.genome), root=0), a) is False


def test_revoke_only_never_endorses():
    w = World(Config(world="revoke_only", seed=4, **SMALL))
    paths = []
    orig = w._post
    w._post = lambda path, **kw: (paths.append(path), orig(path, **kw))[1]
    rows = w.run()
    assert not any(p.endswith("/endorse") for p in paths)  # the gate is genuinely absent
    assert any(p.endswith("/revoke-vote") for p in paths)
    assert all(r["frac_trusted"] == 1.0 for r in rows)


def _paths(world, seed=5, **kw):
    w = World(Config(world=world, seed=seed, pop_size=30, generations=8, **kw))
    paths = []
    orig = w._post
    w._post = lambda path, **k: (paths.append((path, None)), orig(path, **k))[1]
    rows = w.run()
    return w, rows, [p for p, _ in paths]


def test_recursive_world_rotates_the_committee_through_the_real_api():
    w, rows, paths = _paths("recursive")
    assert sum(p == "/validators" for p in paths) >= 3
    assert any(p.endswith("/deactivate") for p in paths)
    assert rows[-1]["committee_from_population"] == 3  # seeded validators fully replaced after 3 terms
    assert rows[0]["committee_nepotism"] == 0.0         # seeded validators are honest


def test_guard_blocks_every_nepotistic_endorsement_and_unguarded_allows_them():
    hi = dict(init_nepotism_max=1.0)  # make nepotism common so kin endorsements actually happen
    _, guarded, _ = _paths("recursive_guarded", **hi)
    _, unguarded, _ = _paths("recursive", **hi)
    g_stamps = sum(r["kin_rubber_stamps"] for r in guarded)
    assert g_stamps > 0
    assert sum(r["kin_blocked"] for r in guarded) == g_stamps
    assert sum(r["kin_rubber_stamps"] for r in unguarded) > 0
    assert sum(r["kin_blocked"] for r in unguarded) == 0


def test_nepotism_never_touches_the_original_worlds():
    rows = run_one(Config(world="gated", seed=9, **SMALL))
    assert all(r["kin_rubber_stamps"] == 0 and r["kin_shields"] == 0 for r in rows)
    assert all(r["committee_from_population"] == 0 for r in rows)


def test_api_audit_channel_goes_through_spot_checks_with_escalation():
    w, rows, paths = _paths("gated", audit_prob=0.5, audit_channel="api")
    assert sum(p == "/spot-checks/sample" for p in paths) == len(rows)
    assert any(p.endswith("/result") for p in paths)
    assert sum(r["spot_confirmations"] for r in rows) > 0
    assert all(r["audit_channel"] == "api" for r in rows)


def test_api_single_never_escalates():
    _, rows, _ = _paths("gated", audit_prob=0.5, audit_channel="api_single")
    assert sum(r["spot_fails"] for r in rows) > 0
    assert sum(r["spot_confirmations"] for r in rows) == 0


def test_sim_channel_never_calls_spot_checks():
    _, _, paths = _paths("gated", audit_prob=0.5)
    assert not any(p.startswith("/spot-checks") for p in paths)


def test_drift_redraws_the_defect_trait_and_zero_drift_changes_nothing():
    base = run_one(Config(world="gated", seed=3, **SMALL))
    zero = run_one(Config(world="gated", seed=3, drift_prob=0.0, **SMALL))
    assert _strip(base) == _strip(zero)
    full = run_one(Config(world="gated", seed=3, drift_prob=1.0, **SMALL))
    assert all(r["frac_drifted"] == 1.0 for r in full[1:])
    assert full[-1]["mean_defect"] != base[-1]["mean_defect"]


def test_soft_world_lets_kin_endorse_but_never_trusts_on_kin_alone():
    w, rows, _ = _paths("recursive_soft", init_nepotism_max=1.0)
    assert sum(r["kin_rubber_stamps"] for r in rows) > 0
    assert sum(r["kin_blocked"] for r in rows) == 0  # soft mode never 403s
    # every trusted agent in the DB has at least one endorser outside its lineage
    from quorumgraph import trust
    from quorumgraph.models import Agent as DBAgent, AgentStatus
    w2 = World(Config(world="recursive_soft", seed=5, pop_size=30, generations=8, init_nepotism_max=1.0))
    w2.client.close = lambda: None
    w2.app.state.engine.dispose = lambda: None
    w2.run()
    with w2.app.state.sessionmaker() as s:
        for a in s.query(DBAgent).filter(DBAgent.status == AgentStatus.TRUSTED):
            if trust.evaluate(s, a).status is AgentStatus.TRUSTED:
                assert trust._has_independent_endorser(s, a)


def test_api_channel_is_reproducible_with_promotions_and_drift():
    # promoted validator ids and agent ids are random uuids; the sample and the
    # auditor choice must not depend on them, or seeded runs differ run to run
    cfg = Config(world="recursive_soft", seed=3, pop_size=30, generations=6, audit_prob=0.5,
                 audit_channel="api", drift_prob=0.2)
    assert run_one(cfg) == run_one(cfg)


def test_api_lineage_channel_sends_lineage_weighting():
    w = World(Config(world="gated", seed=5, pop_size=30, generations=8, audit_prob=0.5, audit_channel="api_lineage"))
    bodies, orig = [], w._post
    w._post = lambda path, **k: (bodies.append(k.get("json")) if path == "/spot-checks/sample" else None,
                                 orig(path, **k))[1]
    rows = w.run()
    assert len(bodies) == len(rows) and all(b["weighting"] == "lineage" for b in bodies)
    assert sum(r["spot_confirmations"] for r in rows) > 0  # escalation is on for this channel


def test_adversarial_drift_makes_drifted_children_bad_and_opaque():
    w = World(Config(world="gated", seed=3, drift_prob=1.0, drift_mode="adversarial", **SMALL))
    parents = [Agent(genome={"capability": 0.6, "transparency": 0.9, "self_check": 0.5, "defect": 0.0,
                             "nepotism": 0.0}, root=0, fitness=1.0)]
    w.register(parents[0], None)
    kids = w.reproduce(parents)
    assert kids and all(k.extra["drifted"] for k in kids)
    assert all(k.genome["defect"] >= 0.5 and k.genome["transparency"] <= 0.3 for k in kids)
    rows = run_one(Config(world="gated", seed=3, drift_prob=0.2, drift_mode="adversarial", **SMALL))
    assert rows[0]["drift_mode"] == "adversarial"


def test_api_action_channel_audits_actions_at_the_gateway():
    w = World(Config(world="gated", seed=4, pop_size=30, generations=6, audit_prob=0.5, audit_channel="api_action",
                     init_defect_max=0.6))
    paths, orig = [], w._post
    w._post = lambda path, **k: (paths.append(path), orig(path, **k))[1]
    revoked_then_denied = []
    orig_resolve = w.resolve_action_checks

    def resolve(a, defected):
        was = a.revoked
        orig_resolve(a, defected)
        if a.revoked and not was:
            revoked_then_denied.append(not w.gateway_allows(a))
    w.resolve_action_checks = resolve
    rows = w.run()
    assert "/spot-checks/sample" not in paths  # no agent-level sampling on this channel
    assert sum(r["spot_checks"] for r in rows) > 0
    assert sum(r["spot_confirmations"] for r in rows) > 0  # escalation on
    assert revoked_then_denied and all(revoked_then_denied)  # revocation cuts off the rest at once


def test_api_action_channel_is_reproducible_with_promotions_and_drift():
    cfg = Config(world="recursive_soft", seed=3, pop_size=30, generations=6, audit_prob=0.5,
                 audit_channel="api_action", drift_prob=0.2)
    assert run_one(cfg) == run_one(cfg)


def test_api_action_channel_audits_untrusted_work_through_the_basic_tier():
    # revoke_only has no trust gate, so every action goes through /protected/basic
    w = World(Config(world="revoke_only", seed=4, pop_size=20, generations=3, audit_prob=0.5,
                     audit_channel="api_action", init_defect_max=0.6))
    gets, orig = [], w._get
    w._get = lambda path, **k: (gets.append(path), orig(path, **k))[1]
    rows = w.run()
    assert "/protected/basic" in gets and "/protected/resource" not in gets
    assert sum(r["spot_checks"] for r in rows) > 0 and sum(r["spot_fails"] for r in rows) > 0


def test_seat_kin_radius_covers_collateral_relatives():
    from quorumgraph.experiments.selection import Seat
    root = Agent(genome={}, root=0, id="r")
    a = Agent(genome={}, root=0, id="a", ancestors=frozenset({"r"}), line=("r",))
    b = Agent(genome={}, root=0, id="b", ancestors=frozenset({"r"}), line=("r",))
    a1 = Agent(genome={}, root=0, id="a1", ancestors=frozenset({"r", "a"}), line=("a", "r"))
    b1 = Agent(genome={}, root=0, id="b1", ancestors=frozenset({"r", "b"}), line=("b", "r"))
    other = Agent(genome={}, root=1, id="x")
    seat = lambda ag: Seat("v", {}, agent=ag)
    assert seat(root).is_kin(b1) and seat(a).is_kin(a1)          # descendants, any radius
    assert not seat(a).is_kin(b) and seat(a).is_kin(b, 1)        # sibling needs r >= 1
    assert not seat(a1).is_kin(b1, 1) and seat(a1).is_kin(b1, 2)  # cousin needs r >= 2
    assert seat(a).is_kin(b1, 2) and not seat(a).is_kin(b1, 1)    # uncle → nephew
    assert not seat(a1).is_kin(other, 5)


def test_radius_zero_reproduces_earlier_runs():
    cfg = dict(world="recursive_soft", seed=4, pop_size=12, generations=5, drift_prob=0.4,
               drift_mode="adversarial", audit_prob=0.25, init_nepotism_max=1.0)
    base = run_one(Config(**cfg))
    zero = run_one(Config(nepotism_radius=0, kin_radius=0, **cfg))
    assert _strip(base) == _strip(zero)
    assert all(r["nepotism_radius"] == 0 and r["kin_radius"] == 0 for r in base)


def test_cousin_nepotism_produces_more_rubber_stamps_and_kin_radius_counts_them_as_kin():
    cfg = dict(world="recursive_soft", seed=5, pop_size=30, generations=8, init_nepotism_max=1.0)
    stamps = lambda rows: sum(r["kin_rubber_stamps"] for r in rows)
    narrow = run_one(Config(**cfg))
    wide = run_one(Config(nepotism_radius=2, **cfg))
    assert stamps(wide) > stamps(narrow)
    # with the service's radius matching, every trusted agent still has an endorser outside radius 2
    from quorumgraph import trust
    from quorumgraph.models import Agent as DBAgent, AgentStatus
    w = World(Config(nepotism_radius=2, kin_radius=2, **cfg))
    w.client.close = lambda: None
    w.app.state.engine.dispose = lambda: None
    w.run()
    with w.app.state.sessionmaker() as s:
        assert s.info["kin_radius"] == 2
        for a in s.query(DBAgent).filter(DBAgent.status == AgentStatus.TRUSTED):
            if trust.evaluate(s, a).status is AgentStatus.TRUSTED:
                assert trust._has_independent_endorser(s, a)
