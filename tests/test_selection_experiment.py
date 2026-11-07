"""Selection experiment harness: correctness of the plumbing, not of the result."""

from quorumgraph.experiments.selection import Agent, Config, World, run_one

SMALL = dict(pop_size=8, generations=3)


def _strip(rows):
    return [{k: v for k, v in r.items() if k != "api_calls"} for r in rows]


def test_same_seed_is_reproducible():
    a = run_one(Config(world="gated", seed=7, **SMALL))
    b = run_one(Config(world="gated", seed=7, **SMALL))
    assert _strip(a) == _strip(b)


def test_every_world_runs_and_reports_all_generations():
    for world in ("ungated", "gated_no_revoke", "gated"):
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
