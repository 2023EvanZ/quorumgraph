"""Chaos soak test: random concurrent workload + SIGKILL crashes + invariant checks.

    uv run python -m quorumgraph.experiments.soak --duration 8h
    uv run python -m quorumgraph.experiments.soak --duration 2m          # smoke test

Topology: the trust service and two gateways run as SEPARATE PROCESSES
(uvicorn). The fault injector crashes them with SIGKILL (no graceful
shutdown, possibly mid-transaction) and restarts them on the same ports.

  Gateway A  mode=ttl         TTL 2 s
  Gateway B  mode=invalidate  TTL 60 s  (so prompt denials can only come from invalidation)

Online invariants (checked on every response):
  I1  B never allows a revoked agent for a request started > B_BOUND after the
      revocation was acknowledged to the client.
  I2  A never allows a revoked agent for a request started > TTL + A_SLACK after
      acknowledgement.
  I3  No gateway allows an agent before it could possibly be trusted (request
      completed before the first endorsement for it was even sent).
  I4  No HTTP 500 from any service. (503 from a gateway = expected fail-closed
      during an outage; connection errors while a process is down = expected.)

Offline invariants (checked on the database at the end):
  O1  Each agent's status transitions are one of: none, p→t, p→t→r, p→r.
  O2  agents.status equals the last recorded transition (or pending).
  O3  trusted ⇒ ≥ 2 endorsements; revoked ⇒ ≥ 2 revocation votes.
  O4  Every revocation acknowledged to the client is revoked in the DB.

Writes to runs/soak-<timestamp>/: progress.json (every 60 s), violations.jsonl
(as they happen), report.md + report.json (at the end), and server logs.
Exit code 1 if any invariant was violated.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import httpx

GATEWAY_SECRET = "soak-gateway-secret"
TTL_A, TTL_B = 2.0, 60.0
B_BOUND = 1.0        # seconds after revocation ack within which B must deny
A_SLACK = 2.0        # extra slack on top of A's TTL (fetch in flight + scheduling)
VALIDATORS = ("validator-a", "validator-b", "validator-c")


def parse_duration(s: str) -> float:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([smh]?)", s.strip())
    if not m:
        raise argparse.ArgumentTypeError(f"bad duration {s!r} (use e.g. 90s, 15m, 8h)")
    return float(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600}[m.group(2)]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --- process management ----------------------------------------------------------

class Service:
    def __init__(self, name: str, factory: str, port: int, env: dict, log_dir: Path):
        self.name, self.factory, self.port = name, factory, port
        self.env = {**os.environ, **env}
        self.log = open(log_dir / f"{name}.log", "ab")
        self.proc: subprocess.Popen | None = None
        self.url = f"http://127.0.0.1:{port}"
        self.crashes = 0

    def start(self, timeout: float = 20.0) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", self.factory, "--factory", "--port", str(self.port),
             "--log-level", "warning"],
            env=self.env, stdout=self.log, stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if httpx.get(self.url + "/openapi.json", timeout=0.5).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.name} exited during startup (see {self.log.name})")
            time.sleep(0.05)
        raise RuntimeError(f"{self.name} didn't start within {timeout}s")

    def kill(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGKILL)  # crash: no cleanup, possibly mid-transaction
            self.proc.wait()
            self.crashes += 1

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# --- client-side ledger ------------------------------------------------------------

@dataclass
class Tracked:
    id: str
    token: str
    first_endorse_sent: float | None = None
    revoked_ack: float | None = None
    trusted_ack: bool = False


@dataclass
class Ledger:
    lock: threading.Lock = field(default_factory=threading.Lock)
    agents: dict[str, Tracked] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)
    counts: Counter = field(default_factory=Counter)
    violations: list[dict] = field(default_factory=list)
    vfile: object = None
    revoked_acked: set[str] = field(default_factory=set)  # kept forever, for O4
    keep: int = 5000                                        # agents kept in memory for the workload

    def add(self, t: Tracked) -> None:
        with self.lock:
            self.agents[t.id] = t
            self.order.append(t.id)
            if len(self.order) > 2 * self.keep:  # bounded memory over an 8 h run
                for old in self.order[: -self.keep]:
                    self.agents.pop(old, None)
                self.order = self.order[-self.keep:]
                self.counts["agents_evicted_from_memory"] += 1

    def pick(self, rng: random.Random, recent: int = 300) -> Tracked | None:
        with self.lock:
            if not self.order:
                return None
            return self.agents[rng.choice(self.order[-recent:])]

    def count(self, key: str, n: int = 1) -> None:
        with self.lock:
            self.counts[key] += n

    def violate(self, kind: str, **ctx) -> None:
        rec = {"invariant": kind, "at": datetime.now().isoformat(timespec="milliseconds"), **ctx}
        with self.lock:
            self.violations.append(rec)
            if self.vfile:
                self.vfile.write(json.dumps(rec) + "\n")
                self.vfile.flush()


# --- workload ---------------------------------------------------------------------

def worker(idx: int, stop: threading.Event, ledger: Ledger, trust: Service, gw: dict[str, Service],
           vtok: dict[str, str], seed: int, op_interval: float) -> None:
    rng = random.Random(seed * 1000 + idx)
    vh = {k: {"Authorization": f"Bearer {t}"} for k, t in vtok.items()}
    client = httpx.Client(timeout=5.0)
    ops = (["access"] * 70) + (["register"] * 8) + (["endorse"] * 14) + (["revoke"] * 8)

    def call(method, url, **kw):
        try:
            return client.request(method, url, **kw)
        except httpx.HTTPError:
            ledger.count("conn_errors")
            return None

    next_at = time.monotonic()
    while not stop.is_set():
        if op_interval:
            next_at += op_interval
            if (delay := next_at - time.monotonic()) > 0:
                stop.wait(delay)
            else:
                next_at = time.monotonic()  # fell behind (e.g. outage timeouts): don't burst to catch up
        op = rng.choice(ops)
        ledger.count(f"op_{op}")
        if op == "register":
            parent = ledger.pick(rng) if rng.random() < 0.3 else None
            body, headers = {"name": f"soak-{idx}"}, {}
            if parent:
                body["parent_agent_id"] = parent.id
                headers = {"Authorization": f"Bearer {parent.token}"}
            r = call("POST", trust.url + "/agents", json=body, headers=headers)
            if r is None:
                continue
            if r.status_code >= 500:
                ledger.violate("I4", service="trust", op=op, status=r.status_code, body=r.text[:300])
            elif r.status_code == 201:
                d = r.json()
                ledger.add(Tracked(d["id"], d["token"]))
            continue

        agent = ledger.pick(rng)
        if agent is None:
            continue

        if op in ("endorse", "revoke"):
            vid = rng.choice(VALIDATORS)
            sent = time.monotonic()
            if op == "endorse":
                with ledger.lock:
                    if agent.first_endorse_sent is None:
                        agent.first_endorse_sent = sent
                r = call("POST", f"{trust.url}/agents/{agent.id}/endorse", headers=vh[vid])
            else:
                r = call("POST", f"{trust.url}/agents/{agent.id}/revoke-vote", json={"reason": "soak"}, headers=vh[vid])
            if r is None:
                continue
            if r.status_code >= 500:
                ledger.violate("I4", service="trust", op=op, status=r.status_code, body=r.text[:300])
            elif r.status_code == 201:
                st = r.json()["agent_status"]
                with ledger.lock:
                    if st == "revoked" and agent.revoked_ack is None:
                        agent.revoked_ack = time.monotonic()
                        ledger.revoked_acked.add(agent.id)
                    if st == "trusted":
                        agent.trusted_ack = True
            ledger.count(f"{op}_{r.status_code}")
            continue

        # access through a random gateway
        name = rng.choice(("A", "B"))
        start = time.monotonic()
        r = call("GET", gw[name].url + "/protected/resource", headers={"Authorization": f"Bearer {agent.token}"})
        end = time.monotonic()
        if r is None:
            continue
        ledger.count(f"access_{name}_{r.status_code}")
        if r.status_code == 500:
            ledger.violate("I4", service=f"gateway-{name}", status=500, body=r.text[:300])
        if r.status_code != 200:
            continue
        with ledger.lock:
            rev, first_e = agent.revoked_ack, agent.first_endorse_sent
        if first_e is None or end < first_e:
            ledger.violate("I3", gateway=name, agent=agent.id, detail="allowed before any endorsement was sent")
        if rev is not None:
            late = start - rev
            if name == "B" and late > B_BOUND:
                ledger.violate("I1", gateway="B", agent=agent.id, seconds_after_revocation=round(late, 3),
                               cache=r.headers.get("x-qg-cache"))
            if name == "A" and late > TTL_A + A_SLACK:
                ledger.violate("I2", gateway="A", agent=agent.id, seconds_after_revocation=round(late, 3),
                               cache=r.headers.get("x-qg-cache"))
    client.close()


def fault_injector(stop: threading.Event, ledger: Ledger, services: dict[str, Service], rng: random.Random,
                   min_gap: float, max_gap: float, log) -> None:
    while not stop.wait(rng.uniform(min_gap, max_gap)):
        name = rng.choice(list(services))
        svc = services[name]
        down = rng.uniform(0.3, 3.0)
        log(f"fault: SIGKILL {name}, down {down:.1f}s")
        svc.kill()
        ledger.count(f"fault_kill_{name}")
        if stop.wait(down):
            break
        try:
            svc.start()
        except RuntimeError as e:
            ledger.violate("RESTART", service=name, error=str(e))
            log(f"restart of {name} FAILED: {e}")


# --- offline checks ------------------------------------------------------------------

def offline_checks(db_path: Path, ledger: Ledger) -> dict:
    con = sqlite3.connect(db_path)
    trans: dict[str, list[tuple[str, str]]] = {}
    for agent_id, details in con.execute(
        "SELECT agent_id, details FROM audit_events WHERE event_type='agent_status_changed' ORDER BY id"
    ):
        d = json.loads(details)
        trans.setdefault(agent_id, []).append((d["old"], d["new"]))
    status = dict(con.execute("SELECT id, status FROM agents"))
    endorse = dict(con.execute("SELECT agent_id, COUNT(*) FROM endorsements GROUP BY agent_id"))
    votes = dict(con.execute("SELECT agent_id, COUNT(*) FROM revocation_votes GROUP BY agent_id"))
    con.close()

    allowed = {(), (("pending", "trusted"),), (("pending", "trusted"), ("trusted", "revoked")),
               (("pending", "revoked"),)}
    found = Counter()
    for aid, st in status.items():
        seq = tuple(trans.get(aid, []))
        if seq not in allowed:
            found["O1"] += 1
            ledger.violate("O1", agent=aid, transitions=seq)
        expected = seq[-1][1] if seq else "pending"
        if st.lower() != expected:
            found["O2"] += 1
            ledger.violate("O2", agent=aid, stored=st, expected=expected)
        if st.lower() == "trusted" and endorse.get(aid, 0) < 2:
            found["O3"] += 1
            ledger.violate("O3", agent=aid, status=st, endorsements=endorse.get(aid, 0))
        if st.lower() == "revoked" and votes.get(aid, 0) < 2:
            found["O3"] += 1
            ledger.violate("O3", agent=aid, status=st, votes=votes.get(aid, 0))
    for aid in ledger.revoked_acked:
        if status.get(aid, "").lower() != "revoked":
            found["O4"] += 1
            ledger.violate("O4", agent=aid, stored=status.get(aid))
    return {"agents_in_db": len(status), "agents_with_transitions": len(trans),
            "revoked_in_db": sum(1 for s in status.values() if s.lower() == "revoked"),
            "trusted_in_db": sum(1 for s in status.values() if s.lower() == "trusted"), **found}


# --- main ----------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--duration", type=parse_duration, default=parse_duration("8h"))
    p.add_argument("--workers", type=int, default=6)
    p.add_argument("--rate", type=float, default=300.0, help="target total ops/s (0 = unthrottled)")
    p.add_argument("--sabotage", choices=["b-ttl-only"], default=None,
                   help="deliberately break gateway B (run it TTL-only) to prove the checker catches it")
    p.add_argument("--fault-min", type=float, default=20.0, help="min seconds between crashes")
    p.add_argument("--fault-max", type=float, default=60.0, help="max seconds between crashes")
    p.add_argument("--seed", type=int, default=int(time.time()))
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args(argv)

    out = args.out or Path("runs") / f"soak-{datetime.now():%Y%m%d-%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    db_path = (out / "soak.db").resolve()

    def log(msg: str) -> None:
        line = f"[{datetime.now():%H:%M:%S}] {msg}"
        print(line, flush=True)
        with open(out / "soak.log", "a") as f:
            f.write(line + "\n")

    # Seed validators directly into the DB before the trust service starts.
    from ..db import Base, make_engine
    from sqlalchemy.orm import sessionmaker
    from ..seed import seed_validators
    engine = make_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    with sessionmaker(engine)() as s:
        vtok = seed_validators(s)
        s.commit()
    engine.dispose()

    tport, aport, bport = free_port(), free_port(), free_port()
    trust = Service("trust", "quorumgraph.main:create_app", tport,
                    {"QG_DATABASE_URL": f"sqlite:///{db_path}", "QG_GATEWAY_SECRET": GATEWAY_SECRET,
                     "QG_EVENT_POLL_INTERVAL": "0.02"}, out)
    common = {"QG_TRUST_URL": trust.url, "QG_GATEWAY_SECRET": GATEWAY_SECRET}
    gw = {
        "A": Service("gateway-A", "quorumgraph.gateway:create_gateway_app_from_env", aport,
                     {**common, "QG_GATEWAY_NAME": "A", "QG_GATEWAY_MODE": "ttl", "QG_GATEWAY_TTL": str(TTL_A)}, out),
        "B": Service("gateway-B", "quorumgraph.gateway:create_gateway_app_from_env", bport,
                     {**common, "QG_GATEWAY_NAME": "B", "QG_GATEWAY_TTL": str(TTL_B),
                      "QG_GATEWAY_MODE": "ttl" if args.sabotage == "b-ttl-only" else "invalidate"}, out),
    }
    services = {"trust": trust, "gateway-A": gw["A"], "gateway-B": gw["B"]}

    ledger = Ledger(vfile=open(out / "violations.jsonl", "a"))
    config = {"duration_s": args.duration, "workers": args.workers, "rate": args.rate, "sabotage": args.sabotage,
              "seed": args.seed,
              "fault_gap_s": [args.fault_min, args.fault_max], "ttl_a": TTL_A, "ttl_b": TTL_B,
              "b_bound_s": B_BOUND, "a_slack_s": A_SLACK, "ports": [tport, aport, bport]}
    (out / "config.json").write_text(json.dumps(config, indent=2))

    stop = threading.Event()
    threads: list[threading.Thread] = []
    t0 = time.monotonic()
    try:
        for svc in services.values():
            svc.start()
        log(f"soak start: {args.duration / 3600:.2f} h, {args.workers} workers, seed {args.seed} → {out}")
        for i in range(args.workers):
            interval = args.workers / args.rate if args.rate else 0.0
            threads.append(threading.Thread(target=worker, daemon=True,
                                            args=(i, stop, ledger, trust, gw, vtok, args.seed, interval)))
        threads.append(threading.Thread(target=fault_injector, daemon=True,
                                        args=(stop, ledger, services, random.Random(args.seed), args.fault_min, args.fault_max, log)))
        for t in threads:
            t.start()

        next_report = time.monotonic() + 60
        while (elapsed := time.monotonic() - t0) < args.duration:
            time.sleep(min(1.0, args.duration - elapsed))
            if time.monotonic() >= next_report or time.monotonic() - t0 >= args.duration:
                next_report = time.monotonic() + 60
                with ledger.lock:
                    snap = {"elapsed_s": round(time.monotonic() - t0), "agents": len(ledger.agents),
                            "violations": len(ledger.violations), "counts": dict(ledger.counts)}
                (out / "progress.json").write_text(json.dumps(snap, indent=2))
                total = sum(v for k, v in snap["counts"].items() if k.startswith("op_"))
                log(f"{snap['elapsed_s'] / 60:.0f} min: {total} ops, {snap['agents']} agents, "
                    f"{snap['violations']} violations")
    except KeyboardInterrupt:
        log("interrupted; finishing up")
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=10)
        for svc in services.values():
            svc.stop()

    offline = offline_checks(db_path, ledger)
    elapsed = time.monotonic() - t0
    by_inv = Counter(v["invariant"] for v in ledger.violations)
    c = ledger.counts
    total_ops = sum(v for k, v in c.items() if k.startswith("op_"))
    report = {"config": config, "elapsed_s": round(elapsed), "total_ops": total_ops,
              "ops_per_s": round(total_ops / elapsed, 1), "crashes": {n: s.crashes for n, s in services.items()},
              "violations_by_invariant": dict(by_inv), "offline": offline, "counts": dict(c)}
    (out / "report.json").write_text(json.dumps(report, indent=2))

    md = [f"# Soak report\n",
          f"- Duration: {elapsed / 3600:.2f} h, {total_ops:,} operations ({report['ops_per_s']}/s), {args.workers} workers",
          f"- SIGKILL crashes: " + ", ".join(f"{n} ×{s.crashes}" for n, s in services.items()),
          f"- Agents: {offline['agents_in_db']:,} in DB ({offline['trusted_in_db']:,} trusted, {offline['revoked_in_db']:,} revoked)",
          f"- Gateway A: {c['access_A_200']:,} allow / {c['access_A_403']:,} deny / {c['access_A_503']:,} fail-closed",
          f"- Gateway B: {c['access_B_200']:,} allow / {c['access_B_403']:,} deny / {c['access_B_503']:,} fail-closed",
          f"- Connection errors (expected while a process is down): {c['conn_errors']:,}",
          f"\n## Invariants\n",
          "| invariant | violations |", "|---|---|"]
    for inv, desc in [("I1", "B denies revoked agent within 1 s"), ("I2", "A denies revoked agent within TTL + 2 s"),
                      ("I3", "no allow before any endorsement"), ("I4", "no HTTP 500"),
                      ("O1", "valid transition sequences"), ("O2", "stored status matches last transition"),
                      ("O3", "status backed by ≥ 2 votes"), ("O4", "acknowledged revocations persisted"),
                      ("RESTART", "crashed services restart")]:
        md.append(f"| {inv}: {desc} | {by_inv.get(inv, 0)} |")
    md.append(f"\n**{'PASS' if not ledger.violations else 'FAIL'}**: {len(ledger.violations)} violation(s). "
              "Details in violations.jsonl.")
    (out / "report.md").write_text("\n".join(md) + "\n")
    log("\n".join(md))
    return 1 if ledger.violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
