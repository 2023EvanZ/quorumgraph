"""Measure revocation propagation latency: TTL-only gateway vs. invalidating gateway.

    uv run python -m quorumgraph.propagation                # defaults: 10 trials, TTL 3s
    uv run python -m quorumgraph.propagation --trials 20 --ttl 5

Starts, on real sockets, a trust service (temp SQLite DB), Gateway A (mode=ttl)
and Gateway B (mode=invalidate). Per trial:

  1. register an agent, endorse it to trusted
  2. warm both gateways' caches (one request each)
  3. revoke it by quorum; t0 = when the deciding vote's response arrives
  4. hammer both gateways every ~5 ms until each returns 403
  5. record latency and how many stale ALLOWs each served after t0

Latency is measured from the client's view of the commit acknowledgement, so it
includes network + event-poll + delivery time, which is what an attacker
holding a revoked token actually experiences.
"""

import argparse
import statistics
import tempfile
import time
from pathlib import Path

import httpx

from .gateway import create_gateway_app
from .main import create_app
from .seed import seed_validators
from .servers import ServerThread

SECRET = "propagation-benchmark-secret"


def _wait_ready(client: httpx.Client, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if client.get("/gateway/stats").json().get("stream_ready"):
            return
        time.sleep(0.02)
    raise RuntimeError("invalidating gateway never became ready")


def _pct(values: list[float], p: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, round(p / 100 * (len(s) - 1)))]


def run(trials: int = 10, ttl: float = 3.0, poll_interval: float = 0.05, out=print) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        trust_app = create_app(
            f"sqlite:///{Path(tmp) / 'bench.db'}", gateway_secret=SECRET, event_poll_interval=poll_interval
        )
        with trust_app.state.sessionmaker() as s:
            vtok = seed_validators(s)
            s.commit()

        with ServerThread(trust_app) as trust:
            gw_a_app = create_gateway_app(trust_url=trust.url, gateway_secret=SECRET, name="A", mode="ttl", ttl=ttl)
            gw_b_app = create_gateway_app(
                trust_url=trust.url, gateway_secret=SECRET, name="B", mode="invalidate", ttl=ttl
            )
            with ServerThread(gw_a_app) as a, ServerThread(gw_b_app) as b, \
                    httpx.Client(base_url=trust.url, timeout=5) as tc, \
                    httpx.Client(base_url=a.url, timeout=5) as ac, \
                    httpx.Client(base_url=b.url, timeout=5) as bc:
                _wait_ready(bc)
                v = {k: {"Authorization": f"Bearer {t}"} for k, t in vtok.items()}
                res = {"A": [], "B": []}
                stale = {"A": [], "B": []}

                out(f"trust={trust.url}  A(ttl={ttl}s)={a.url}  B(invalidate, poll={poll_interval * 1000:.0f}ms)={b.url}")
                for i in range(trials):
                    agent = tc.post("/agents", json={"name": f"bench-{i}"}).json()
                    for vid in ("validator-a", "validator-b"):
                        tc.post(f"/agents/{agent['id']}/endorse", headers=v[vid]).raise_for_status()
                    h = {"Authorization": f"Bearer {agent['token']}"}
                    for c in (ac, bc):  # warm caches
                        assert c.get("/protected/resource", headers=h).status_code == 200

                    tc.post(f"/agents/{agent['id']}/revoke-vote", json={"reason": "bench"}, headers=v["validator-a"])
                    r = tc.post(f"/agents/{agent['id']}/revoke-vote", json={"reason": "bench"}, headers=v["validator-c"])
                    t0 = time.perf_counter()
                    assert r.json()["agent_status"] == "revoked"

                    pending = {"A": ac, "B": bc}
                    stale_count = {"A": 0, "B": 0}
                    deadline = t0 + ttl + 5
                    while pending and time.perf_counter() < deadline:
                        for name, c in list(pending.items()):
                            code = c.get("/protected/resource", headers=h).status_code
                            if code == 200:
                                stale_count[name] += 1
                            elif code == 403:
                                res[name].append(time.perf_counter() - t0)
                                stale[name].append(stale_count[name])
                                del pending[name]
                        time.sleep(0.005)
                    if pending:
                        raise RuntimeError(f"trial {i}: gateways {list(pending)} never denied")
                    out(f"  trial {i + 1:>2}: A {res['A'][-1] * 1000:7.1f} ms ({stale_count['A']:>3} stale allows)"
                        f"   B {res['B'][-1] * 1000:6.1f} ms ({stale_count['B']} stale allows)")

                summary = {
                    name: {
                        "median_ms": statistics.median(lat) * 1000,
                        "p95_ms": _pct(lat, 95) * 1000,
                        "max_ms": max(lat) * 1000,
                        "stale_allows_total": sum(stale[name]),
                    }
                    for name, lat in res.items()
                }
                out("")
                out(f"  {'gateway':<16} {'median':>9} {'p95':>9} {'max':>9}  stale allows served")
                for name, label in (("A", "A (ttl only)"), ("B", "B (invalidate)")):
                    m = summary[name]
                    out(f"  {label:<16} {m['median_ms']:>7.1f}ms {m['p95_ms']:>7.1f}ms {m['max_ms']:>7.1f}ms"
                        f"  {m['stale_allows_total']}")
                out("")
                out("  B stats: " + str({k: val for k, val in bc.get("/gateway/stats").json().items()
                                          if k in ("invalidations", "entries_evicted", "stale_put_refused",
                                                   "stream_connects", "stream_errors")}))
                return summary


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--trials", type=int, default=10)
    p.add_argument("--ttl", type=float, default=3.0, help="gateway cache TTL in seconds")
    p.add_argument("--poll-interval", type=float, default=0.05, help="trust service outbox poll interval (s)")
    args = p.parse_args(argv)
    run(args.trials, args.ttl, args.poll_interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
