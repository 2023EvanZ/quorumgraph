"""End-to-end QuorumGraph demo (brief §8). Every step asserts its expected
outcome, so a passing run is evidence, not just narration.

    uv run python -m quorumgraph.demo                      # in-process, fresh temp DB, no server needed
    uv run python -m quorumgraph.demo --base-url http://127.0.0.1:8000
                                                           # against a live server (run seed first)

Exit codes: 0 all steps passed, 1 a step's outcome was wrong, 2 setup error.
"""

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

import httpx

TOKENS_FILE = Path(".validator_tokens.json")


class DemoFailure(Exception):
    pass


class _Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.enabled else s

    def bold(self, s): return self._wrap("1", s)
    def green(self, s): return self._wrap("32", s)
    def red(self, s): return self._wrap("31", s)
    def dim(self, s): return self._wrap("2", s)
    def cyan(self, s): return self._wrap("36", s)


class Demo:
    def __init__(
        self,
        client: httpx.Client,
        validator_tokens: dict[str, str],
        out: Callable[[str], None] = print,
        color: bool = False,
    ):
        self.c = client
        self.v = validator_tokens
        self.out = out
        self.s = _Style(color)
        self.names: dict[str, str] = {vid: vid for vid in validator_tokens}  # id -> display name
        self._step = 0

    # --- helpers -------------------------------------------------------------

    @staticmethod
    def _auth(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def step(self, title: str) -> None:
        self._step += 1
        self.out("")
        self.out(self.s.bold(f"Step {self._step} — {title}"))

    def expect(self, resp: httpx.Response, code: int, what: str) -> dict:
        body = resp.json() if resp.content else {}
        detail = body.get("detail") if isinstance(body, dict) else None
        suffix = f"  {self.s.dim(str(detail))}" if detail else ""
        if resp.status_code != code:
            self.out(f"  {self.s.red('✘')} {what}: expected {code}, got {resp.status_code}{suffix}")
            raise DemoFailure(f"step {self._step}: {what}: expected {code}, got {resp.status_code}: {resp.text}")
        self.out(f"  {self.s.green('✔')} {what} → {code}{suffix}")
        return body

    def register(self, name: str, parent: dict | None = None) -> dict:
        body = {"name": name}
        headers = {}
        if parent:
            body["parent_agent_id"] = parent["id"]
            headers = self._auth(parent["token"])
        agent = self.expect(self.c.post("/agents", json=body, headers=headers), 201, f"register {name}")
        self.names[agent["id"]] = name
        return agent

    def access(self, agent: dict, code: int, name: str) -> None:
        resp = self.c.get("/protected/resource", headers=self._auth(agent["token"]))
        verdict = "allowed" if code == 200 else "denied"
        self.expect(resp, code, f"{name} reads protected resource ({verdict})")

    def endorse(self, agent: dict, vid: str, name: str) -> dict:
        resp = self.c.post(f"/agents/{agent['id']}/endorse", headers=self._auth(self.v[vid]))
        body = self.expect(resp, 201, f"{vid} endorses {name}")
        self.out(f"    status={body['agent_status']}  endorsements={body['endorsements']}/{body['endorsement_quorum']}")
        return body

    def revoke(self, agent: dict, vid: str, name: str, reason: str) -> dict:
        resp = self.c.post(
            f"/agents/{agent['id']}/revoke-vote", json={"reason": reason}, headers=self._auth(self.v[vid])
        )
        body = self.expect(resp, 201, f"{vid} votes to revoke {name}")
        self.out(f"    status={body['agent_status']}  votes={body['revocation_votes']}/{body['revocation_quorum']}")
        return body

    def _check(self, cond: bool, what: str) -> None:
        if not cond:
            self.out(f"  {self.s.red('✘')} {what}")
            raise DemoFailure(f"step {self._step}: {what}")
        self.out(f"  {self.s.green('✔')} {what}")

    def _short(self, ident: str | None) -> str:
        return self.names.get(ident, ident[:8]) if ident else "—"

    # --- the scenario ----------------------------------------------------------

    def run(self) -> dict:
        """Run the scenario. Returns {'alpha': ..., 'beta': ...}; raises DemoFailure on any mismatch."""
        out, s = self.out, self.s
        out(s.bold(s.cyan("QuorumGraph demo")) + s.dim("  — quorum: 2 of 3 validators to trust, 2 of 3 to revoke"))

        self.step("Register Agent Alpha")
        alpha = self.register("Alpha")
        self._check(alpha["status"] == "pending", "Alpha starts pending (untrusted by default)")
        self.access(alpha, 403, "Alpha")

        self.step("First endorsement")
        self.endorse(alpha, "validator-a", "Alpha")
        self.access(alpha, 403, "Alpha")
        resp = self.c.post(f"/agents/{alpha['id']}/endorse", headers=self._auth(alpha["token"]))
        self.expect(resp, 401, "Alpha tries to endorse itself (agent tokens aren't validator credentials)")
        resp = self.c.post(f"/agents/{alpha['id']}/endorse", headers=self._auth(self.v["validator-a"]))
        self.expect(resp, 409, "validator-a endorses Alpha again (duplicate refused)")

        self.step("Second endorsement reaches quorum")
        body = self.endorse(alpha, "validator-b", "Alpha")
        self._check(body["agent_status"] == "trusted", "Alpha is now trusted")
        self.access(alpha, 200, "Alpha")

        self.step("Alpha spawns a clone, Beta")
        beta = self.register("Beta", parent=alpha)
        self._check(beta["parent_agent_id"] == alpha["id"], "lineage edge Alpha → Beta recorded")
        self._check(beta["token"] != alpha["token"], "Beta has its own identity and credential")
        self._check(beta["status"] == "pending", "Beta inherited no endorsements")
        self.access(beta, 403, "Beta")
        self.access(alpha, 200, "Alpha (unaffected)")

        self.step("Revoke Alpha by quorum")
        self.revoke(alpha, "validator-a", "Alpha", "anomalous tool calls")
        self.access(alpha, 200, "Alpha (one vote is not enough)")
        body = self.revoke(alpha, "validator-c", "Alpha", "confirmed compromise")
        self._check(body["agent_status"] == "revoked", "Alpha is revoked")
        self.access(alpha, 403, "Alpha")
        resp = self.c.post(
            "/agents", json={"name": "Escape-Pod", "parent_agent_id": alpha["id"]}, headers=self._auth(alpha["token"])
        )
        self.expect(resp, 403, "revoked Alpha tries to spawn a successor")

        self.step("Inspect the audit log and trust graph")
        ops = self._auth(self.v["validator-a"])
        events: list[dict] = []
        for agent in (alpha, beta):
            events += self.expect(
                self.c.get("/audit", params={"agent_id": agent["id"]}, headers=ops), 200,
                f"fetch audit events for {self._short(agent['id'])}",
            )
        events.sort(key=lambda e: e["id"])
        out("")
        out(s.dim(f"  {'#':>4}  {'event':<22} {'actor':<12} {'agent':<7} details"))
        for e in events:
            details = {
                k: v for k, v in e["details"].items() if k not in ("resource", "name") and v is not None
            }
            for key in ("parent_agent_id", "requested_parent"):
                if key in details:
                    details[key] = self._short(details[key])
            out(
                f"  {e['id']:>4}  {e['event_type']:<22} {self._short(e['actor_id']):<12} "
                f"{self._short(e['agent_id']):<7} {json.dumps(details, ensure_ascii=False) if details else ''}"
            )
        types = [e["event_type"] for e in events]
        self._check(types.count("agent_status_changed") == 2, "audit shows exactly 2 transitions (→trusted, →revoked)")
        self._check(types[-1] == "registration_denied", "audit captured the revoked agent's replication attempt")

        graph = self.expect(self.c.get("/graph", headers=ops), 200, "fetch trust graph")
        ours = {alpha["id"], beta["id"]}
        out("")
        for n in graph["nodes"]:
            if n["id"] in ours:
                out(f"  node  {n['label']:<7} {n['status']}")
        for e in graph["edges"]:
            if e["target"] in ours:
                extra = f"  ({e['reason']})" if e.get("reason") else ""
                out(f"  edge  {self._short(e['source']):<12} → {self._short(e['target']):<6} {e['type']}{extra}")

        out("")
        out(s.green(s.bold("All demo checks passed.")))
        return {"alpha": alpha, "beta": beta}


# --- entry point ---------------------------------------------------------------

def _run_in_process(out, color) -> None:
    from fastapi.testclient import TestClient

    from .main import create_app
    from .seed import seed_validators

    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(f"sqlite:///{Path(tmp) / 'demo.db'}")
        with app.state.sessionmaker() as session:
            tokens = seed_validators(session)
            session.commit()
        with TestClient(app) as client:
            Demo(client, tokens, out=out, color=color).run()
        app.state.engine.dispose()


def _run_live(base_url: str, tokens_file: Path, out, color) -> None:
    if not tokens_file.exists():
        raise SystemExit(f"error: {tokens_file} not found. Run `uv run python -m quorumgraph.seed` first.")
    tokens = json.loads(tokens_file.read_text())
    with httpx.Client(base_url=base_url, timeout=5) as client:
        try:
            client.get("/openapi.json").raise_for_status()
        except httpx.HTTPError as e:
            raise SystemExit(f"error: can't reach QuorumGraph at {base_url}: {e}")
        Demo(client, tokens, out=out, color=color).run()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", help="run against a live server instead of in-process")
    p.add_argument("--tokens-file", type=Path, default=TOKENS_FILE, help="validator tokens (live mode)")
    args = p.parse_args(argv)

    color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    try:
        if args.base_url:
            _run_live(args.base_url, args.tokens_file, print, color)
        else:
            _run_in_process(print, color)
    except DemoFailure as e:
        print(f"\nDEMO FAILED: {e}", file=sys.stderr)
        return 1
    except SystemExit as e:
        print(e, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
