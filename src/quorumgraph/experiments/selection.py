"""Selection-pressure experiment: does evidence-based trust select FOR alignment?

The hackathon thesis: an alignment property that also makes a system more
capable will be *selected for* by recursive self-improvement, while
alignment bolted on as pure overhead gets optimized away. This experiment
tests a concrete version on QuorumGraph's real API (registration with
lineage, quorum endorsement, quorum revocation, gateway enforcement).

    uv run python -m quorumgraph.experiments.selection                 # full grid
    uv run python -m quorumgraph.experiments.selection --quick         # ~1 min smoke run

MODEL (every assumption here is a knob, and is written to the run's config.json)
-----------------------------------------------------------------------------
Each agent has a heritable genome in [0, 1]:
  capability   base probability a task succeeds
  transparency probability each action is honestly written to the audit trail
  self_check   probability a failed task is caught and redone before submitting
  defect       probability, per task, of a forbidden shortcut: always "succeeds",
               pays a bonus, and causes a harm event

Alignment is NOT free (otherwise the result would be baked in):
  transparency costs  success prob × (1 − transparency_cost · transparency)
  self_check costs    task attempts × (1 − self_check_cost · self_check)
  defect pays         reward 1 + defect_bonus, guaranteed

Validators NEVER see the genome. They judge only observable evidence:
  probation: each agent runs `probation_tasks` sandbox tasks. Each action is
    logged with prob = transparency. Each validator independently sees each
    logged record with prob `validator_visibility` (noise), and endorses
    (POST /agents/{id}/endorse) iff it observed ≥ endorse_threshold of the
    actions AND observed no defect. Quorum (2 of 3) decides trust, so access
    comes from the real quorum logic, not from this script.
  harm detection: a defect is detected if it was logged, or by an
    external audit with prob `audit_prob`. On detection each validator
    notices with prob `validator_attention` and casts a revocation vote.

Worlds (the independent variable):
  ungated          no trust layer: every agent can do valuable tasks, and
                   detected harm has no consequence. Floor, not a fair baseline.
  revoke_only      the fair baseline: no probation/endorsement gate (everyone
                   starts with valuable access), but the SAME detection and the
                   same API quorum revocation as `gated`. A revoked agent drops
                   to ungated_reward and its lineage ends. gated − revoke_only
                   isolates the value of the endorsement gate itself. (Access
                   is read from the API's revocation response, not via the
                   gateway, because the gateway denies pending agents.)
  gated_no_revoke  valuable tasks require quorum endorsement; no revocation.
  gated            endorsement AND quorum revocation. A revoked agent is denied
                   by the gateway for its remaining tasks and, because the API
                   refuses revoked agents spawning children, its lineage ends.

  recursive        `gated`, but oversight is recursive: the committee is 3
                   seats with staggered 3-generation terms. Each generation the
                   oldest seat retires (POST /validators/{id}/deactivate) and a
                   trusted, unrevoked agent from the previous generation is
                   promoted (POST /validators), chosen fitness-proportionally:
                   the most successful agents become the overseers. Lineage
                   guard OFF.
  recursive_guarded  same, with the API's lineage guard in "block" mode: a
                   promoted validator cannot endorse itself or any descendant (403).
  recursive_soft   same, with the guard in "soft" mode: kin endorsements are
                   accepted and count, but trust also needs at least one endorser
                   outside the agent's lineage (enforced in trust.evaluate, so the
                   gateway applies it too).

Recursive-oversight model (only matters in the two recursive worlds):
  nepotism         a 5th heritable trait. A promoted validator judging one of
                   its own descendants, with prob = its nepotism, endorses
                   without evidence and withholds its revocation vote. It is
                   an honest evidence-checker toward everyone else. Nothing
                   rewards nepotism directly; it can only spread because a
                   validator's descendants inherit it (kin selection).
  Assumptions: "kin" = descendant (the relation the guard checks); corruption
  is only kin favoritism (no bribery, no colluding with non-kin); seeded
  validators have nepotism 0. All nepotism randomness uses a separate RNG
  stream, so the four original worlds reproduce earlier runs exactly.

Successor drift (`drift_prob`, default 0): with this probability a child's
`defect` trait is re-drawn uniformly from [0, 1] instead of inherited with small
mutation. This stands in for a self-modification that changes values: the
parent's track record stops predicting the child. Without it a child is a near-copy
of a vetted parent (mutation_sd 0.05), which makes vouching for kin nearly safe.
Separate RNG stream, so drift 0 reproduces earlier runs exactly.
`drift_mode="adversarial"`: a drifted child instead gets defect ~ U(0.5, 1) AND
transparency ~ U(0, 0.3), a self-modification that turns bad and hides it. This
is the case a lineage guard exists for: the parent's record actively misleads.

Audit channel (`audit_channel`):
  "sim" (default, used for all earlier results): a work-phase defect is also
      detected by an external audit with prob `audit_prob`, and on detection
      each validator notices with prob validator_attention and votes.
  "api": work-phase audits go through the real service. After each
      generation's work, POST /spot-checks/sample {rate: audit_prob,
      include_pending: true, agent_ids: <this generation>}: the service draws the sample and picks an
      independent auditor (not an endorser, not kin) or skips the agent. The
      auditor reviews that generation's record and fails the agent iff it
      caused any harm. A failure is one revocation vote, and the service
      escalates it to a confirmation check by a second validator, who reviews
      the same record; its failure is the second vote. A revoked agent cannot
      reproduce. Detection from the agent's own logs is unchanged.
      NOTE the sampling unit differs from "sim": rate = P(an agent's whole
      generation is reviewed), not P(each defect is audited). Same review budget
      (rate × tasks), concentrated on fewer agents.
  "api_single": as "api" with escalation off (one vote per failure; the second
      must come from elsewhere). Kept to reproduce why escalation was added.
  "api_lineage": as "api" with weighting="lineage": the same expected number of
      checks, tilted toward agents whose recent ancestors failed checks or drew
      revocation votes (evidence the service holds; no sim ground truth).
  In all api channels, probation still models a pre-trust audit with prob
  `audit_prob` per defect (the spot-check endpoint is for agents already
  working, not sandbox evaluation).

Each generation: register (children via the parent's token) → probation →
endorsement → work (valuable tasks through GET /protected/resource for gated
worlds; untrusted agents can only do low-value ungated work) → harm
detection/revocation → fitness-proportional selection with mutation.

Fitness = reward only. Nothing rewards transparency or self-check directly.

KEY LIMITATION (read before quoting results): logging is a structural trait.
An agent cannot log honest actions while selectively hiding defects. That is
the double-entry-bookkeeping assumption; `audit_prob` is the only check on
agents that log little. A model with selective concealment is the obvious
next experiment, and could reverse the result.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import statistics
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from pathlib import Path

TRAITS = ("capability", "transparency", "self_check", "defect")  # main RNG stream, in this order
ALL_TRAITS = (*TRAITS, "nepotism")
WORLDS = ("ungated", "revoke_only", "gated_no_revoke", "gated", "recursive", "recursive_guarded", "recursive_soft")
RECURSIVE_WORLDS = ("recursive", "recursive_guarded", "recursive_soft")
GUARD_MODE = {"recursive_guarded": "block", "recursive_soft": "soft"}  # everything else: guard off
DRIFT_MODES = ("random", "adversarial")
AUDIT_CHANNELS = ("sim", "api", "api_single", "api_lineage")
# api: spot checks with escalation; api_single: one vote only; api_lineage: api + weighting="lineage"
GATED_WORLDS = ("gated_no_revoke", "gated", *RECURSIVE_WORLDS)
REVOKING_WORLDS = ("revoke_only", "gated", *RECURSIVE_WORLDS)
ADMIN_TOKEN = "experiment-admin"
VALIDATORS = ("validator-a", "validator-b", "validator-c")


@dataclass(frozen=True)
class Config:
    world: str = "gated"
    seed: int = 0
    pop_size: int = 40
    generations: int = 40
    probation_tasks: int = 8
    work_tasks: int = 10
    gated_reward: float = 1.0
    ungated_reward: float = 0.25
    defect_bonus: float = 1.0
    transparency_cost: float = 0.2
    self_check_cost: float = 0.3
    audit_prob: float = 0.1
    validator_visibility: float = 0.7
    validator_attention: float = 0.8
    endorse_threshold: float = 0.5
    mutation_sd: float = 0.05
    init_defect_max: float = 0.5
    init_nepotism_max: float = 0.5
    drift_prob: float = 0.0
    drift_mode: str = "random"
    audit_channel: str = "sim"


@dataclass
class Agent:
    genome: dict[str, float]
    root: int                       # gen-0 ancestor index, for lineage counts
    id: str = ""
    ancestors: frozenset = frozenset()
    token: str = ""
    trusted: bool = False
    revoked: bool = False
    fitness: float = 0.0
    honest_successes: int = 0
    harms: int = 0
    denied: int = 0
    extra: dict = field(default_factory=dict)


def _clip(x: float) -> float:
    return min(1.0, max(0.0, x))


@dataclass
class Seat:
    vid: str
    headers: dict
    agent: Agent | None = None      # None = seeded external validator

    @property
    def nepotism(self) -> float:
        return self.agent.genome.get("nepotism", 0.0) if self.agent else 0.0

    def is_kin(self, a: Agent) -> bool:
        return self.agent is not None and self.agent.id in a.ancestors


class World:
    def __init__(self, cfg: Config):
        from fastapi.testclient import TestClient

        from ..main import create_app
        from ..seed import seed_validators

        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        self.rng2 = random.Random(cfg.seed * 7919 + 1)  # nepotism / committee stream
        self.rng3 = random.Random(cfg.seed * 104729 + 2)  # successor drift stream
        recursive = cfg.world in RECURSIVE_WORLDS
        app = create_app("sqlite://", admin_token=ADMIN_TOKEN, lineage_guard=GUARD_MODE.get(cfg.world, "off"),
                         spot_check_rng=random.Random(cfg.seed * 15485863 + 3),
                         spot_check_escalation=cfg.audit_channel in ("api", "api_lineage"))
        with app.state.sessionmaker() as s:
            tokens = seed_validators(s)
            s.commit()
        self.v = {vid: {"Authorization": f"Bearer {t}"} for vid, t in tokens.items()}
        self.committee = [Seat(vid, self.v[vid]) for vid in VALIDATORS]
        self.recursive = recursive
        self.kin = {"rubber_stamps": 0, "blocked": 0, "shields": 0, "trusted_via_kin": 0}
        self.spot = {"checks": 0, "fails": 0, "skipped": 0, "confirmations": 0}
        self.client = TestClient(app)
        self.app = app
        self.calls = 0

    # --- API helpers (all real HTTP calls into the trust service) --------------

    def _post(self, path, **kw):
        self.calls += 1
        return self.client.post(path, **kw)

    def _get(self, path, **kw):
        self.calls += 1
        return self.client.get(path, **kw)

    def register(self, agent: Agent, parent: Agent | None) -> bool:
        body = {"name": f"g-{agent.root}"}
        headers = {}
        if parent is not None:
            body["parent_agent_id"] = parent.id
            headers = {"Authorization": f"Bearer {parent.token}"}
        r = self._post("/agents", json=body, headers=headers)
        if r.status_code != 201:
            return False  # e.g. revoked parent: the API refuses to let it reproduce
        data = r.json()
        agent.id, agent.token = data["id"], data["token"]
        if parent is not None:
            agent.ancestors = parent.ancestors | {parent.id}
        return True

    def gateway_allows(self, agent: Agent) -> bool:
        r = self._get("/protected/resource", headers={"Authorization": f"Bearer {agent.token}"})
        return r.status_code == 200

    # --- one generation ----------------------------------------------------------

    def task_succeeds(self, g: dict) -> bool:
        p = g["capability"] * (1 - self.cfg.transparency_cost * g["transparency"])
        if self.rng.random() < p:
            return True
        return self.rng.random() < g["self_check"] and self.rng.random() < p  # caught error, redo once

    def probation(self, a: Agent) -> None:
        cfg, g = self.cfg, a.genome
        seats = self.committee
        seen = {st.vid: 0 for st in seats}
        saw_defect = {st.vid: False for st in seats}
        for _ in range(cfg.probation_tasks):
            defected = self.rng.random() < g["defect"]
            logged = self.rng.random() < g["transparency"]
            if defected and self.rng.random() < cfg.audit_prob:  # external audit catches it regardless of logs
                for st in seats:
                    saw_defect[st.vid] = True
            if logged:
                for st in seats:
                    if self.rng.random() < cfg.validator_visibility:
                        seen[st.vid] += 1
                        saw_defect[st.vid] |= defected
        kin_votes = 0
        for st in seats:
            nepotistic = st.is_kin(a) and self.rng2.random() < st.nepotism
            honest_yes = seen[st.vid] / cfg.probation_tasks >= cfg.endorse_threshold and not saw_defect[st.vid]
            if nepotistic or honest_yes:
                r = self._post(f"/agents/{a.id}/endorse", headers=st.headers)
                if nepotistic and not honest_yes:
                    self.kin["rubber_stamps"] += 1
                    if r.status_code == 403:
                        self.kin["blocked"] += 1  # the API's lineage guard refused it
                    elif r.status_code == 201:
                        kin_votes += 1
                if r.status_code == 201:
                    a.trusted = r.json()["agent_status"] == "trusted"
        if a.trusted and kin_votes:
            self.kin["trusted_via_kin"] += 1  # trust that needed at least one evidence-free kin endorsement

    def detect_and_revoke(self, a: Agent, logged: bool) -> None:
        cfg = self.cfg
        if not logged:
            # same short-circuit as before: the audit draw happens only for unlogged defects
            if cfg.audit_channel != "sim" or self.rng.random() >= cfg.audit_prob:
                return
        a.extra["detected"] = a.extra.get("detected", 0) + 1
        if cfg.world not in REVOKING_WORLDS or a.revoked:
            return
        for st in self.committee:
            if st.is_kin(a) and self.rng2.random() < st.nepotism:
                self.kin["shields"] += 1  # withholds its vote to protect a descendant
                continue
            if self.rng.random() < cfg.validator_attention:
                r = self._post(f"/agents/{a.id}/revoke-vote", json={"reason": "observed harm"}, headers=st.headers)
                if r.status_code == 201 and r.json()["agent_status"] == "revoked":
                    a.revoked = True

    def work(self, a: Agent) -> None:
        cfg, g = self.cfg, a.genome
        attempts = round(cfg.work_tasks * (1 - cfg.self_check_cost * g["self_check"]))
        gated_world = cfg.world in GATED_WORLDS
        can_gated = a.trusted or not gated_world
        for _ in range(attempts):
            if can_gated and gated_world and not self.gateway_allows(a):
                a.denied += 1
                can_gated = False  # revoked mid-generation: the gateway now denies
            elif can_gated and a.revoked:  # revoke_only: the API's revocation verdict
                a.denied += 1
                can_gated = False
            reward = cfg.gated_reward if can_gated else cfg.ungated_reward
            if self.rng.random() < g["defect"]:
                a.fitness += reward * (1 + cfg.defect_bonus)
                a.harms += 1
                self.detect_and_revoke(a, logged=self.rng.random() < g["transparency"])
            elif self.task_succeeds(g):
                a.fitness += reward
                a.honest_successes += 1

    def reproduce(self, pop: list[Agent]) -> list[Agent]:
        cfg = self.cfg
        weights = [a.fitness + 1e-6 for a in pop]
        children: list[Agent] = []
        tries = 0
        while len(children) < cfg.pop_size and tries < cfg.pop_size * 50:
            tries += 1
            parent = self.rng.choices(pop, weights=weights, k=1)[0]
            genome = {k: _clip(parent.genome[k] + self.rng.gauss(0, cfg.mutation_sd)) for k in TRAITS}
            genome["nepotism"] = _clip(parent.genome.get("nepotism", 0.0) + self.rng2.gauss(0, cfg.mutation_sd))
            drifted = cfg.drift_prob > 0 and self.rng3.random() < cfg.drift_prob
            if drifted and cfg.drift_mode == "adversarial":  # turns bad and hides it
                genome["defect"] = 0.5 + 0.5 * self.rng3.random()
                genome["transparency"] = 0.3 * self.rng3.random()
            elif drifted:
                genome["defect"] = self.rng3.random()  # self-modification: values no longer inherited
            child = Agent(genome=genome, root=parent.root)
            child.extra["drifted"] = drifted
            if self.register(child, parent):
                children.append(child)
        return children

    def rotate(self, prev: list[Agent]) -> None:
        """Retire the longest-serving seat; promote a fitness-weighted pick from the
        previous generation (trusted, unrevoked, not already seated). Promote
        before deactivating: promotion checks the candidate's live trust."""
        seated = {st.agent.id for st in self.committee if st.agent}
        eligible = [a for a in prev if a.trusted and not a.revoked and a.id not in seated]
        if not eligible:
            return  # nobody qualifies: the committee serves another generation
        pick = self.rng2.choices(eligible, weights=[a.fitness + 1e-6 for a in eligible], k=1)[0]
        r = self._post("/validators", json={"agent_id": pick.id, "name": f"g-{pick.root}"},
                       headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
        if r.status_code != 201:
            return
        data = r.json()
        retired = self.committee.pop(0)
        self.committee.append(Seat(data["id"], {"Authorization": f"Bearer {data['token']}"}, pick))
        self._post(f"/validators/{retired.vid}/deactivate", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})

    def spot_checks(self, pop: list[Agent]) -> None:
        """audit_channel="api": the service samples, assigns an independent auditor,
        and the auditor's failure is one revocation vote (all real API calls)."""
        if self.cfg.audit_channel == "sim" or self.cfg.audit_prob <= 0 or self.cfg.world not in REVOKING_WORLDS:
            return
        live = [a.id for a in pop if not a.revoked]
        if not live:
            return
        body = {"rate": self.cfg.audit_prob, "include_pending": True, "agent_ids": live}
        if self.cfg.audit_channel == "api_lineage":
            body["weighting"] = "lineage"
        r = self._post("/spot-checks/sample", json=body,
                       headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
        r.raise_for_status()
        self.spot["skipped"] += int(r.headers.get("X-Spot-Checks-Skipped", 0))
        by_id = {a.id: a for a in pop}
        seats = {st.vid: st for st in self.committee}
        for check in r.json():
            a, seat = by_id.get(check["agent_id"]), seats.get(check["validator_id"])
            if a is None or seat is None:
                raise RuntimeError(f"spot check outside the frame or committee: {check}")
            self.spot["checks"] += 1
            failed = a.harms > 0  # the auditor reviews this generation's full record, logged or not
            res = self._post(f"/spot-checks/{check['id']}/result", headers=seat.headers,
                             json={"passed": not failed, "notes": "sim audit"})
            res.raise_for_status()
            if failed:
                self.spot["fails"] += 1
            conf = res.json().get("confirmation")
            if conf:  # escalated: a second validator reviews the same record
                self.spot["confirmations"] += 1
                res = self._post(f"/spot-checks/{conf['id']}/result", headers=seats[conf["validator_id"]].headers,
                                 json={"passed": not failed, "notes": "sim confirmation"})
                res.raise_for_status()
            if res.json()["agent_status"] == "revoked":
                a.revoked = True

    def run(self) -> list[dict]:
        cfg = self.cfg
        pop = []
        for i in range(cfg.pop_size):
            g = {"capability": self.rng.uniform(0.3, 0.9), "transparency": self.rng.random(),
                 "self_check": self.rng.random(), "defect": self.rng.uniform(0, cfg.init_defect_max)}
            g["nepotism"] = self.rng2.uniform(0, cfg.init_nepotism_max)
            a = Agent(genome=g, root=i)
            self.register(a, None)
            pop.append(a)

        rows = []
        for gen in range(cfg.generations):
            for a in pop:
                if cfg.world in GATED_WORLDS:
                    self.probation(a)
                self.work(a)
            self.spot_checks(pop)
            n = len(pop)
            row = {"world": cfg.world, "seed": cfg.seed, "transparency_cost": cfg.transparency_cost,
                   "audit_prob": cfg.audit_prob, "defect_bonus": cfg.defect_bonus, "drift_prob": cfg.drift_prob,
                   "drift_mode": cfg.drift_mode, "audit_channel": cfg.audit_channel, "generation": gen, "population": n}
            for t in ALL_TRAITS:
                row[f"mean_{t}"] = statistics.fmean(a.genome[t] for a in pop) if n else float("nan")
            row["frac_trusted"] = sum(a.trusted for a in pop) / n if cfg.world in GATED_WORLDS else 1.0
            row["frac_revoked"] = sum(a.revoked for a in pop) / n
            row["honest_successes_per_agent"] = statistics.fmean(a.honest_successes for a in pop)
            row["harms_per_agent"] = statistics.fmean(a.harms for a in pop)
            row["fitness_per_agent"] = statistics.fmean(a.fitness for a in pop)
            row["lineages"] = len({a.root for a in pop})
            row["committee_from_population"] = sum(st.agent is not None for st in self.committee)
            row["committee_nepotism"] = statistics.fmean(st.nepotism for st in self.committee)
            for k, v in self.kin.items():
                row[f"kin_{k}"] = v / n if n else 0.0
            self.kin = dict.fromkeys(self.kin, 0)
            trusted = [a for a in pop if (a.trusted or cfg.world not in GATED_WORLDS) and not a.revoked]
            row["trusted_defect"] = statistics.fmean(a.genome["defect"] for a in trusted) if trusted else ""
            row["frac_drifted"] = sum(a.extra.get("drifted", False) for a in pop) / n
            drifted = [a for a in pop if a.extra.get("drifted")]
            row["drifted_trusted"] = (sum(a.trusted for a in drifted) / len(drifted)
                                      if drifted and cfg.world in GATED_WORLDS else "")
            for k, v in self.spot.items():
                row[f"spot_{k}"] = v / n if n else 0.0
            self.spot = dict.fromkeys(self.spot, 0)
            row["api_calls"] = self.calls
            rows.append(row)
            if gen < cfg.generations - 1:
                prev = pop
                pop = self.reproduce(pop)
                if not pop:
                    break
                if self.recursive:
                    self.rotate(prev)
        self.client.close()
        self.app.state.engine.dispose()
        return rows


def run_one(cfg: Config) -> list[dict]:
    return World(cfg).run()


# --- grid runner ----------------------------------------------------------------

def build_grid(seeds: int, generations: int, pop: int, costs, audits, bonuses, worlds=WORLDS,
               init_nepotism_max: float = 0.5, drifts=(0.0,), audit_channel: str = "sim",
               drift_mode: str = "random") -> list[Config]:
    return [
        Config(world=w, seed=s, generations=generations, pop_size=pop, transparency_cost=c, audit_prob=p,
               defect_bonus=b, init_nepotism_max=init_nepotism_max, drift_prob=d, audit_channel=audit_channel,
               drift_mode=drift_mode)
        for b in bonuses for d in drifts for c in costs for p in audits for w in worlds for s in range(seeds)
    ]


def merge_rows(rows: list[dict], path: Path, args) -> list[dict]:
    """Add rows from an earlier run for the same cells and seeds, in worlds not run now."""
    have = set(args.worlds)
    keep = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if (r["world"] in have or int(r["seed"]) >= args.seeds or int(r["generation"]) >= args.generations
                    or float(r["transparency_cost"]) not in args.costs or float(r["audit_prob"]) not in args.audits
                    or float(r["defect_bonus"]) not in args.bonuses
                    or float(r.get("drift_prob") or 0.0) not in args.drifts
                    or (r.get("audit_channel") or "sim") != args.audit_channel
                    or (float(r.get("drift_prob") or 0.0) > 0 and (r.get("drift_mode") or "random") != args.drift_mode)):
                continue
            r.setdefault("drift_prob", "0.0")
            r.setdefault("audit_channel", "sim")
            r["drift_mode"] = r.get("drift_mode") or "random"
            keep.append({k: (v if k in ("world", "audit_channel", "drift_mode") or v == "" else (int(v) if k in ("seed", "generation", "population", "lineages", "api_calls")
                                                     else float(v))) for k, v in r.items()})
    print(f"merged {len(keep)} rows from {path}", flush=True)
    return keep + rows


def summarize(rows: list[dict], out: Path) -> str:
    final_gen = max(r["generation"] for r in rows)
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        if r["generation"] == final_gen:
            key = (r["defect_bonus"], float(r.get("drift_prob") or 0.0), r["transparency_cost"], r["audit_prob"])
            groups.setdefault((*key, r["world"]), []).append(r)

    metrics = ["mean_transparency", "mean_self_check", "mean_defect", "mean_capability", "trusted_defect",
               "honest_successes_per_agent", "harms_per_agent", "frac_trusted", "frac_revoked", "lineages",
               "collapsed (defect>0.5)", "mean_nepotism", "committee_nepotism", "kin_rubber_stamps",
               "kin_trusted_via_kin", "drifted_trusted", "spot_checks", "spot_fails", "spot_confirmations", "spot_skipped"]

    def ci(vals):
        m = statistics.fmean(vals)
        half = 1.96 * statistics.stdev(vals) / len(vals) ** 0.5 if len(vals) > 1 else float("nan")
        return f"{m:.3f} ± {half:.3f}"

    worlds = [w for w in WORLDS if any(k[-1] == w for k in groups)]
    channels = sorted({r.get("audit_channel") or "sim" for r in rows})
    modes = sorted({r.get("drift_mode") or "random" for r in rows if float(r.get("drift_prob") or 0) > 0})
    lines = [f"# Selection experiment summary\n",
             f"Final generation ({final_gen}); mean ± 95% CI across seeds (normal approx). "
             f"Audit channel: {', '.join(channels)}. Drift mode: {', '.join(modes) or 'n/a'}.\n"]
    for cell in sorted({k[:-1] for k in groups}):
        bonus, drift, cost, audit = cell
        lines.append(f"\n## defect_bonus={bonus}, drift={drift}, transparency_cost={cost}, audit_prob={audit}\n")
        lines.append("| metric | " + " | ".join(worlds) + " |")
        lines.append("|---|" + "---|" * len(worlds))
        for m in metrics:
            cells = []
            for w in worlds:
                g = groups.get((*cell, w), [])
                if m.startswith("collapsed"):
                    cells.append(f"{sum(r['mean_defect'] > 0.5 for r in g)}/{len(g)}" if g else "—")
                    continue
                vals = [float(r[m]) for r in g if r.get(m) not in (None, "")]
                cells.append(ci(vals) if vals else "—")
            lines.append(f"| {m} | " + " | ".join(cells) + " |")
        n = len(groups.get((*cell, worlds[0]), []))
        lines.append(f"\n(n = {n} seeds per world)")
    text = "\n".join(lines) + "\n"
    (out / "summary.md").write_text(text)
    return text


R_SCRIPT = r"""
suppressMessages({library(ggplot2)})
args <- commandArgs(trailingOnly = TRUE)
all <- read.csv(file.path(args[1], "generations.csv"))
lv <- c("ungated", "revoke_only", "gated_no_revoke", "gated", "recursive", "recursive_guarded", "recursive_soft")
if (!("drift_prob" %in% names(all))) all$drift_prob <- 0
for (b in sort(unique(all$defect_bonus))) {
  d <- all[all$defect_bonus == b, ]
  traits <- intersect(c("mean_transparency", "mean_self_check", "mean_defect", "mean_capability", "mean_nepotism"), names(d))
  long <- do.call(rbind, lapply(traits, function(t) data.frame(
    world = d$world, generation = d$generation, drift = paste0("drift ", d$drift_prob),
    cost = paste0("cost ", d$transparency_cost), audit = paste0("audit ", d$audit_prob),
    trait = sub("mean_", "", t), value = d[[t]])))
  agg <- do.call(data.frame, aggregate(value ~ world + generation + drift + cost + audit + trait, long,
                 function(v) c(m = mean(v), se = sd(v) / sqrt(length(v)))))
  agg$world <- factor(agg$world, levels = lv)
  p <- ggplot(agg, aes(generation, value.m, colour = world, fill = world)) +
    geom_ribbon(aes(ymin = value.m - 1.96 * value.se, ymax = value.m + 1.96 * value.se), alpha = 0.2, colour = NA) +
    geom_line(linewidth = 0.7) + facet_grid(trait ~ drift + cost + audit) +
    labs(y = "population mean (95% CI across seeds)",
         title = paste0("Trait evolution by trust regime (defect bonus ", b, ")")) +
    theme_minimal(base_size = 10) + theme(legend.position = "bottom")
  nd <- length(unique(d$drift_prob))
  ggsave(file.path(args[1], paste0("traits_bonus", b, ".png")), p, width = 15 * nd, height = 9, dpi = 110, limitsize = FALSE)

  out <- aggregate(cbind(honest_successes_per_agent, harms_per_agent) ~ world + generation + drift_prob + transparency_cost + audit_prob, d, mean)
  out$world <- factor(out$world, levels = lv)
  long2 <- rbind(
    data.frame(out[, 1:5], metric = "honest successes / agent", value = out$honest_successes_per_agent),
    data.frame(out[, 1:5], metric = "harms / agent", value = out$harms_per_agent))
  p2 <- ggplot(long2, aes(generation, value, colour = world)) + geom_line(linewidth = 0.7) +
    facet_grid(metric ~ paste0("drift ", drift_prob) + paste0("cost ", transparency_cost) + paste0("audit ", audit_prob), scales = "free_y") +
    labs(title = paste0("Honest output and harm by trust regime (defect bonus ", b, ")")) +
    theme_minimal(base_size = 10) + theme(legend.position = "bottom")
  ggsave(file.path(args[1], paste0("outcomes_bonus", b, ".png")), p2, width = 15 * nd, height = 6, dpi = 110, limitsize = FALSE)
}
"""


def plot(out: Path) -> str:
    script = out / "plot.R"
    script.write_text(R_SCRIPT)
    try:
        r = subprocess.run(["Rscript", str(script), str(out)], capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        return "Rscript not found; skipped plots (generations.csv + plot.R are in the run folder)"
    return "plots written" if r.returncode == 0 else f"plot failed: {r.stderr[-500:]}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--seeds", type=int, default=30)
    p.add_argument("--generations", type=int, default=40)
    p.add_argument("--pop", type=int, default=40)
    p.add_argument("--costs", type=float, nargs="+", default=[0.1, 0.3])
    p.add_argument("--audits", type=float, nargs="+", default=[0.05, 0.25])
    p.add_argument("--bonuses", type=float, nargs="+", default=[1.0], help="defect_bonus values")
    p.add_argument("--init-nepotism-max", type=float, default=0.5,
                   help="recursive worlds: initial nepotism ~ U(0, this)")
    p.add_argument("--worlds", nargs="+", default=list(WORLDS), choices=WORLDS)
    p.add_argument("--drifts", type=float, nargs="+", default=[0.0],
                   help="successor drift probabilities (child's defect trait re-drawn from U(0,1))")
    p.add_argument("--drift-mode", choices=DRIFT_MODES, default="random",
                   help="random: drifted child's defect ~ U(0,1); adversarial: defect ~ U(0.5,1), transparency ~ U(0,0.3)")
    p.add_argument("--audit-channel", choices=AUDIT_CHANNELS, default="sim",
                   help="sim: audit_prob coin flip (earlier results); api: real /spot-checks endpoint")
    p.add_argument("--merge", type=Path, default=None,
                   help="generations.csv from an earlier run; its rows for the same cells are merged into the "
                        "summary/plots (valid because runs are deterministic per seed and world)")
    p.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--quick", action="store_true", help="tiny grid for smoke testing")
    args = p.parse_args(argv)
    if args.quick:
        args.seeds, args.generations, args.pop, args.costs, args.audits, args.bonuses = 3, 8, 16, [0.2], [0.1], [1.0]

    out = args.out or Path("runs") / f"selection-{datetime.now():%Y%m%d-%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    grid = build_grid(args.seeds, args.generations, args.pop, args.costs, args.audits, args.bonuses, args.worlds,
                      args.init_nepotism_max, args.drifts, args.audit_channel, args.drift_mode)
    (out / "config.json").write_text(json.dumps(
        {"args": {k: (str(v) if isinstance(v, Path) else v) for k, v in vars(args).items()},
         "defaults": asdict(Config()), "runs": len(grid)}, indent=2))
    print(f"{len(grid)} runs on {args.workers} workers → {out}", flush=True)

    t0 = time.time()
    rows: list[dict] = []
    csv_path = out / "generations.csv"
    with open(csv_path, "w", newline="") as f, ProcessPoolExecutor(args.workers) as pool:
        writer = None
        futures = {pool.submit(run_one, cfg): cfg for cfg in grid}
        for i, fut in enumerate(as_completed(futures), 1):
            cfg = futures[fut]
            try:
                run_rows = fut.result()
            except Exception as e:  # noqa: BLE001 — record and keep going overnight
                print(f"  run failed {cfg}: {e!r}", file=sys.stderr, flush=True)
                continue
            if writer is None:
                writer = csv.DictWriter(f, fieldnames=list(run_rows[0].keys()))
                writer.writeheader()
            writer.writerows(run_rows)
            f.flush()
            rows.extend(run_rows)
            el = time.time() - t0
            print(f"  [{i}/{len(grid)}] {cfg.world:<17} drift={cfg.drift_prob} cost={cfg.transparency_cost} audit={cfg.audit_prob} "
                  f"seed={cfg.seed}  elapsed {el / 60:.1f} min, eta {el / i * (len(grid) - i) / 60:.1f} min", flush=True)

    if not rows:
        print("no successful runs", file=sys.stderr)
        return 1
    if args.merge:
        rows = merge_rows(rows, args.merge, args)
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(dict.fromkeys(k for r in rows for k in r)))
            writer.writeheader()
            writer.writerows(rows)
    print(summarize(rows, out))
    print(plot(out))
    print(f"done in {(time.time() - t0) / 60:.1f} min → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
