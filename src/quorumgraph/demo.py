"""End-to-end QuorumGraph demo (brief §8). Every step asserts its expected
outcome, so a passing run is evidence, not just narration.

    uv run python -m quorumgraph.demo                      # in-process, fresh temp DB, no server needed
    uv run python -m quorumgraph.demo --base-url http://127.0.0.1:8000
                                                           # against a live server (run seed first)

Act 1 (always): quorum trust, clones inherit nothing, quorum revocation.
Act 2 (needs an admin token): recursive oversight. A trusted agent is promoted
to validator; a quorum made only of the agent's own lineage leaves it pending
(soft lineage guard); a spot check by an independent auditor fails, escalates to
a second validator, and the confirmation revokes. In-process mode makes a
throwaway admin token; live mode reads QG_ADMIN_TOKEN from the environment
(never a CLI flag, so it doesn't show up in `ps`), and the server must run with
QG_LINEAGE_GUARD=soft (the default).

Exit codes: 0 all steps passed, 1 a step's outcome was wrong, 2 setup error.
"""

import argparse
import json
import os
import random
import secrets
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
        body = self.expect(resp, 201, f"{self.names.get(vid, vid)} endorses {name}")
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


    def run_oversight(self, admin_token: str) -> dict:
        """Act 2: recursive oversight. Returns the agents; raises DemoFailure on any mismatch."""
        out, s = self.out, self.s
        admin = self._auth(admin_token)
        out("")
        out(s.bold(s.cyan("Act 2: recursive oversight")) + s.dim("  — agents become validators; kin can't vouch alone"))
        me = self.expect(self.c.get("/operator/me", headers=admin), 200, "admin token accepted")
        self._check(me.get("lineage_guard") == "soft", f"server runs the soft lineage guard (got {me.get('lineage_guard')})")

        def promote(agent: dict, name: str) -> str:
            v = self.expect(self.c.post("/validators", json={"agent_id": agent["id"], "name": name}, headers=admin),
                            201, f"admin promotes {self._short(agent['id'])} to validator {name}")
            self.v[v["id"]], self.names[v["id"]] = v["token"], name
            return v["id"]

        self.step("Promote a trusted agent to validator")
        atlas = self.register("Atlas")
        self.endorse(atlas, "validator-a", "Atlas")
        self.endorse(atlas, "validator-b", "Atlas")
        resp = self.c.post("/validators", json={"agent_id": atlas["id"], "name": "x"},
                           headers=self._auth(self.v["validator-a"]))
        self.expect(resp, 401, "validator-a tries to appoint a validator (only the admin can)")
        atlas_v = promote(atlas, "Atlas-v")

        self.step("Grow the lineage: Atlas → Atlas-2 → Atlas-3")
        atlas2 = self.register("Atlas-2", parent=atlas)
        self.endorse(atlas2, "validator-a", "Atlas-2")
        self.endorse(atlas2, "validator-b", "Atlas-2")
        atlas2_v = promote(atlas2, "Atlas-2-v")
        atlas3 = self.register("Atlas-3", parent=atlas2)

        self.step("Kin-only quorum: counted, but not enough")
        self.endorse(atlas3, atlas_v, "Atlas-3")
        body = self.endorse(atlas3, atlas2_v, "Atlas-3")
        self._check(body["agent_status"] == "pending" and body["endorsements"] >= body["endorsement_quorum"],
                    "2/2 endorsements, both from Atlas-3's own ancestors → still pending")
        view = self.expect(self.c.get(f"/agents/{atlas3['id']}"), 200, "fetch Atlas-3's trust view")
        self._check(view["needs_independent"] is True, "trust view says it needs an independent endorser")
        self.access(atlas3, 403, "Atlas-3")
        body = self.endorse(atlas3, "validator-c", "Atlas-3")
        self._check(body["agent_status"] == "trusted", "one endorser outside the lineage → trusted")
        self.access(atlas3, 200, "Atlas-3")

        self.step("Spot check: independent auditor, escalation, revocation")
        checks = self.expect(self.c.post("/spot-checks/sample", json={"rate": 1, "agent_ids": [atlas3["id"]]},
                                         headers=admin), 201, "admin draws a spot-check sample (service picks the auditor)")
        self._check(len(checks) == 1, "Atlas-3 was sampled")
        check = checks[0]
        kin, endorsers = {atlas_v, atlas2_v}, {atlas_v, atlas2_v, "validator-c"}
        self._check(check["validator_id"] not in endorsers,
                    f"auditor {self._short(check['validator_id'])} neither endorsed Atlas-3 nor is its kin")
        res = self.expect(self.c.post(f"/spot-checks/{check['id']}/result", json={"passed": False, "notes": "demo"},
                                      headers=self._auth(self.v[check["validator_id"]])), 200,
                          f"{self._short(check['validator_id'])} fails the check")
        self._check(res["agent_status"] == "trusted", "one failed check is one revocation vote: not revoked yet")
        conf = res["confirmation"]
        self._check(conf is not None and conf["validator_id"] not in kin | {check["validator_id"]},
                    f"escalated to a second validator, {self._short(conf and conf['validator_id'])} (not the auditor, not kin)")
        res = self.expect(self.c.post(f"/spot-checks/{conf['id']}/result", json={"passed": False, "notes": "demo"},
                                      headers=self._auth(self.v[conf["validator_id"]])), 200,
                          f"{self._short(conf['validator_id'])} confirms the failure")
        self._check(res["agent_status"] == "revoked" and res["confirmation"] is None,
                    "second vote reaches quorum → revoked; confirmations never escalate again")
        self.access(atlas3, 403, "Atlas-3")

        events = self.expect(self.c.get("/audit", params={"agent_id": atlas3["id"]}, headers=admin), 200,
                             "fetch Atlas-3's audit trail")
        out("")
        for e in sorted(events, key=lambda e: e["id"]):
            out(f"  {e['id']:>4}  {e['event_type']:<24} {self._short(e['actor_id']):<12}")
        types = {e["event_type"] for e in events}
        self._check({"spot_check_assigned", "spot_check_failed", "spot_check_escalated"} <= types,
                    "audit trail records assignment, failures and the escalation")
        out("")
        out(s.green(s.bold("Recursive oversight checks passed.")))
        return {"atlas": atlas, "atlas2": atlas2, "atlas3": atlas3}


# --- entry point ---------------------------------------------------------------

def _run_in_process(out, color) -> None:
    from fastapi.testclient import TestClient

    from .main import create_app
    from .seed import seed_validators

    with tempfile.TemporaryDirectory() as tmp:
        admin_token = secrets.token_urlsafe(16)  # throwaway; never printed
        app = create_app(f"sqlite:///{Path(tmp) / 'demo.db'}", admin_token=admin_token, lineage_guard="soft",
                         spot_check_rng=random.Random(0), spot_check_escalation=True)
        with app.state.sessionmaker() as session:
            tokens = seed_validators(session)
            session.commit()
        with TestClient(app) as client:
            demo = Demo(client, tokens, out=out, color=color)
            demo.run()
            demo.run_oversight(admin_token)
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
        demo = Demo(client, tokens, out=out, color=color)
        demo.run()
        admin_token = os.environ.get("QG_ADMIN_TOKEN")
        if admin_token:
            demo.run_oversight(admin_token)
        else:
            out("\nAct 2 (recursive oversight) skipped: set QG_ADMIN_TOKEN to the server's admin token to run it.")


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
