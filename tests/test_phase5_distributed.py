"""Phase 5: standalone gateways, decision caching, revocation propagation, fail-closed.

Live tests run the trust service and gateways on real sockets (ServerThread),
so HTTP, the SSE stream, and outages behave as they would across processes.
"""

import time

import httpx
import pytest
from fastapi.testclient import TestClient

from quorumgraph.gateway import Decision, DecisionCache, Gateway, create_gateway_app
from quorumgraph.main import create_app
from quorumgraph.security import hash_token
from quorumgraph.seed import seed_validators
from quorumgraph.servers import ServerThread

SECRET = "test-gateway-secret"


def wait_for(predicate, timeout: float = 5.0, interval: float = 0.01):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if (result := predicate()):
            return result
        time.sleep(interval)
    raise AssertionError("condition not met within timeout")


# --- Internal endpoint auth and contract (in-process) ---------------------------

@pytest.fixture
def trust_client():
    app = create_app("sqlite://", gateway_secret=SECRET)
    with app.state.sessionmaker() as s:
        tokens = seed_validators(s)
        s.commit()
    with TestClient(app) as c:
        yield c, tokens


def test_internal_endpoints_require_gateway_key(trust_client):
    c, _ = trust_client
    body = {"token_hash": "0" * 64}
    assert c.post("/internal/authorize", json=body).status_code == 401
    assert c.post("/internal/authorize", json=body, headers={"X-Gateway-Key": "wrong"}).status_code == 401
    assert c.post("/internal/authorize", json=body, headers={"X-Gateway-Key": SECRET}).status_code == 404


def test_internal_endpoints_fail_closed_without_configured_secret():
    with TestClient(create_app("sqlite://", gateway_secret="")) as c:
        r = c.post("/internal/authorize", json={"token_hash": "0" * 64}, headers={"X-Gateway-Key": ""})
        assert r.status_code == 503


def test_authorize_contract(trust_client):
    c, v = trust_client
    k = {"X-Gateway-Key": SECRET}
    agent = c.post("/agents", json={"name": "alpha"}).json()
    th = hash_token(agent["token"])

    assert c.post("/internal/authorize", json={"token_hash": "not-a-hash"}, headers=k).status_code == 422
    d = c.post("/internal/authorize", json={"token_hash": th}, headers=k).json()
    assert d["allowed"] is False and d["status"] == "pending"

    for vid in ("validator-a", "validator-b"):
        c.post(f"/agents/{agent['id']}/endorse", headers={"Authorization": f"Bearer {v[vid]}"})
    d = c.post("/internal/authorize", json={"token_hash": th}, headers=k).json()
    assert d["allowed"] is True and d["agent_id"] == agent["id"]
    # The cursor covers the pending->trusted event that this decision reflects.
    events = c.get("/audit", params={"event_type": "agent_status_changed"},
                   headers={"Authorization": f"Bearer {v['validator-a']}"}).json()
    assert d["as_of_event_id"] >= events[0]["id"]


# --- DecisionCache / Gateway units ----------------------------------------------

def _decision(as_of: int, allowed: bool = True, agent_id: str = "agent-1") -> Decision:
    return Decision(agent_id=agent_id, allowed=allowed, status="trusted" if allowed else "revoked",
                    reason="", as_of_event_id=as_of)


def test_cache_ttl_expiry():
    now = [100.0]
    cache = DecisionCache(ttl=5, clock=lambda: now[0])
    cache.put("h1", _decision(1))
    assert cache.get("h1") is not None
    now[0] += 4.99
    assert cache.get("h1") is not None
    now[0] += 0.02
    assert cache.get("h1") is None
    assert len(cache) == 0


def test_cache_invalidation_evicts_and_refuses_older_decisions():
    cache = DecisionCache(ttl=60)
    cache.put("h1", _decision(10))
    assert cache.invalidate_agent("agent-1", event_id=11) == 1
    assert cache.get("h1") is None
    # A decision computed before event 11 (in flight during the invalidation) must not be cached...
    assert cache.put("h1", _decision(10)) is False
    # ...but one computed after it may be.
    assert cache.put("h1", _decision(11, allowed=False)) is True
    # Other agents are unaffected by agent-1's floor.
    assert cache.put("h2", _decision(5, agent_id="agent-2")) is True


def test_cache_keeps_entries_that_already_reflect_the_event():
    """Event 11 arriving after we cached a decision computed at as_of=11 must not evict it."""
    cache = DecisionCache(ttl=60)
    cache.put("h1", _decision(11))
    assert cache.invalidate_agent("agent-1", event_id=11) == 0
    assert cache.get("h1") is not None
    assert cache.invalidate_agent("agent-1", event_id=12) == 1
    assert cache.get("h1") is None


def test_gateway_refetches_when_decision_raced_an_invalidation():
    gw = Gateway(name="t", trust_url="http://unused", gateway_secret="x", mode="invalidate", ttl=60)
    gw.stream_ready = True
    gw.cache.invalidate_agent("agent-1", event_id=11)  # revocation event already applied
    answers = iter([_decision(10, allowed=True), _decision(12, allowed=False)])  # stale ALLOW, then fresh DENY
    gw.fetch = lambda _h: next(answers)

    decision, result = gw.authorize("h1")
    assert decision.allowed is False and result == "miss"
    assert gw.stats["stale_put_refused"] == 1
    gw.http.close()


# --- Live cluster ----------------------------------------------------------------

class Cluster:
    def __init__(self, tmp_path, ttl_a: float, ttl_b: float):
        self.trust_app = create_app(f"sqlite:///{tmp_path / 'qg.db'}", gateway_secret=SECRET, event_poll_interval=0.02)
        with self.trust_app.state.sessionmaker() as s:
            self.v = {k: {"Authorization": f"Bearer {t}"} for k, t in seed_validators(s).items()}
            s.commit()
        self.trust = ServerThread(self.trust_app).start()
        self.a = ServerThread(create_gateway_app(
            trust_url=self.trust.url, gateway_secret=SECRET, name="A", mode="ttl", ttl=ttl_a)).start()
        self.b = ServerThread(create_gateway_app(
            trust_url=self.trust.url, gateway_secret=SECRET, name="B", mode="invalidate", ttl=ttl_b)).start()
        self.tc = httpx.Client(base_url=self.trust.url, timeout=5)
        self.ac = httpx.Client(base_url=self.a.url, timeout=5)
        self.bc = httpx.Client(base_url=self.b.url, timeout=5)
        wait_for(lambda: self.bc.get("/gateway/stats").json()["stream_ready"])

    def agent(self, name: str, trusted: bool = True) -> tuple[dict, dict]:
        agent = self.tc.post("/agents", json={"name": name}).json()
        if trusted:
            for vid in ("validator-a", "validator-b"):
                self.tc.post(f"/agents/{agent['id']}/endorse", headers=self.v[vid]).raise_for_status()
        return agent, {"Authorization": f"Bearer {agent['token']}"}

    def revoke(self, agent: dict) -> None:
        for vid in ("validator-a", "validator-c"):
            self.tc.post(f"/agents/{agent['id']}/revoke-vote", json={"reason": "t"}, headers=self.v[vid])

    def close(self) -> None:
        for c in (self.tc, self.ac, self.bc):
            c.close()
        for s in (self.b, self.a, self.trust):
            s.stop()


@pytest.fixture
def cluster(tmp_path):
    # B's TTL is huge on purpose: any prompt denial from B must come from invalidation, not expiry.
    c = Cluster(tmp_path, ttl_a=1.0, ttl_b=60.0)
    yield c
    c.close()


def test_ttl_gateway_serves_stale_allow_until_expiry(cluster):
    agent, h = cluster.agent("alpha")
    first = cluster.ac.get("/protected/resource", headers=h)
    assert first.status_code == 200 and first.headers["x-qg-cache"] == "miss"
    cluster.revoke(agent)

    stale = cluster.ac.get("/protected/resource", headers=h)
    assert stale.status_code == 200, "TTL-only gateway should still serve its cached ALLOW"
    assert stale.headers["x-qg-cache"] == "hit"

    time.sleep(1.1)
    assert cluster.ac.get("/protected/resource", headers=h).status_code == 403


def test_invalidating_gateway_denies_promptly(cluster):
    agent, h = cluster.agent("alpha")
    assert cluster.bc.get("/protected/resource", headers=h).status_code == 200
    assert cluster.bc.get("/protected/resource", headers=h).headers["x-qg-cache"] == "hit"

    cluster.revoke(agent)
    t0 = time.perf_counter()
    wait_for(lambda: cluster.bc.get("/protected/resource", headers=h).status_code == 403, timeout=2)
    assert time.perf_counter() - t0 < 1.0  # vs. a 60 s TTL

    stats = cluster.bc.get("/gateway/stats").json()
    assert stats["invalidations"] >= 2 and stats["entries_evicted"] >= 1


def test_invalidation_also_admits_newly_trusted_agents(cluster):
    """Negative caching cuts both ways: a cached DENY outlives promotion to trusted on A, not on B."""
    agent, h = cluster.agent("late-bloomer", trusted=False)
    assert cluster.ac.get("/protected/resource", headers=h).status_code == 403
    assert cluster.bc.get("/protected/resource", headers=h).status_code == 403
    for vid in ("validator-a", "validator-b"):
        cluster.tc.post(f"/agents/{agent['id']}/endorse", headers=cluster.v[vid]).raise_for_status()

    wait_for(lambda: cluster.bc.get("/protected/resource", headers=h).status_code == 200, timeout=2)
    assert cluster.ac.get("/protected/resource", headers=h).status_code == 403  # stale DENY until TTL


def test_unknown_tokens_get_401_and_are_not_cached(cluster):
    before = cluster.bc.get("/gateway/stats").json()["cache_size"]
    for i in range(5):
        r = cluster.bc.get("/protected/resource", headers={"Authorization": f"Bearer qga_garbage{i}"})
        assert r.status_code == 401
    assert cluster.bc.get("/protected/resource").status_code == 401
    assert cluster.bc.get("/gateway/stats").json()["cache_size"] == before


def test_event_stream_replays_backlog_before_ready(cluster):
    a1, _ = cluster.agent("one")       # pending -> trusted
    cluster.revoke(a1)                 # trusted -> revoked
    a2, _ = cluster.agent("two")       # pending -> trusted

    events = []
    with cluster.tc.stream("GET", "/internal/events", params={"after": 0}, headers={"X-Gateway-Key": SECRET}) as r:
        name = None
        for line in r.iter_lines():
            if line.startswith("event:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("data:"):
                events.append((name, line.split(":", 1)[1].strip()))
                if name == "ready":
                    break
    names = [n for n, _ in events]
    assert names == ["status_changed"] * 3 + ["ready"]
    assert '"new": "revoked"' in events[1][1] and a1["id"] in events[1][1]
    assert a2["id"] in events[2][1]


def test_outage_ttl_gateway_stays_available_invalidating_gateway_fails_closed(tmp_path):
    c = Cluster(tmp_path, ttl_a=60.0, ttl_b=60.0)
    try:
        agent, h = c.agent("alpha")
        for gw in (c.ac, c.bc):
            assert gw.get("/protected/resource", headers=h).status_code == 200  # warm both caches

        c.trust.stop()
        # B notices the stream died (connection close, or ≤3 s read timeout) and stops trusting its cache.
        wait_for(lambda: not c.bc.get("/gateway/stats").json()["stream_ready"], timeout=5)

        assert c.ac.get("/protected/resource", headers=h).status_code == 200  # availability: stale-but-cached
        r = c.bc.get("/protected/resource", headers=h)
        assert r.status_code == 503 and "fail-closed" in r.json()["detail"]
        # Unknown tokens on A can't be verified either: fail closed even in ttl mode.
        assert c.ac.get("/protected/resource", headers={"Authorization": "Bearer qga_x"}).status_code == 503

        # Trust service comes back on the same port: B reconnects, resumes, and serves again.
        c.trust = ServerThread(c.trust_app, port=c.trust.port).start()
        wait_for(lambda: c.bc.get("/gateway/stats").json()["stream_ready"], timeout=8)
        assert c.bc.get("/protected/resource", headers=h).status_code == 200
        assert c.bc.get("/gateway/stats").json()["stream_connects"] >= 2
    finally:
        c.close()


def test_gateway_factory_from_env(monkeypatch):
    from quorumgraph.gateway import create_gateway_app_from_env

    monkeypatch.delenv("QG_GATEWAY_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="QG_GATEWAY_SECRET"):
        create_gateway_app_from_env()

    monkeypatch.setenv("QG_GATEWAY_SECRET", "s")
    monkeypatch.setenv("QG_GATEWAY_MODE", "bogus")
    with pytest.raises(RuntimeError, match="QG_GATEWAY_MODE"):
        create_gateway_app_from_env()

    monkeypatch.setenv("QG_GATEWAY_MODE", "ttl")
    monkeypatch.setenv("QG_GATEWAY_NAME", "Z")
    monkeypatch.setenv("QG_GATEWAY_TTL", "7.5")
    gw = create_gateway_app_from_env().state.gateway
    assert (gw.name, gw.mode, gw.cache.ttl) == ("Z", "ttl", 7.5)
    gw.http.close()
