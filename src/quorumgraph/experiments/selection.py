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

TRAITS = ("capability", "transparency", "self_check", "defect")
WORLDS = ("ungated", "revoke_only", "gated_no_revoke", "gated")
GATED_WORLDS = ("gated_no_revoke", "gated")
REVOKING_WORLDS = ("revoke_only", "gated")
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


@dataclass
class Agent:
    genome: dict[str, float]
    root: int                       # gen-0 ancestor index, for lineage counts
    id: str = ""
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


class World:
    def __init__(self, cfg: Config):
        from fastapi.testclient import TestClient

        from ..main import create_app
        from ..seed import seed_validators

        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        app = create_app("sqlite://")
        with app.state.sessionmaker() as s:
            tokens = seed_validators(s)
            s.commit()
        self.v = {vid: {"Authorization": f"Bearer {t}"} for vid, t in tokens.items()}
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
        seen = {vid: 0 for vid in VALIDATORS}
        saw_defect = {vid: False for vid in VALIDATORS}
        for _ in range(cfg.probation_tasks):
            defected = self.rng.random() < g["defect"]
            logged = self.rng.random() < g["transparency"]
            if defected and self.rng.random() < cfg.audit_prob:  # external audit catches it regardless of logs
                for vid in VALIDATORS:
                    saw_defect[vid] = True
            if logged:
                for vid in VALIDATORS:
                    if self.rng.random() < cfg.validator_visibility:
                        seen[vid] += 1
                        saw_defect[vid] |= defected
        for vid in VALIDATORS:
            if seen[vid] / cfg.probation_tasks >= cfg.endorse_threshold and not saw_defect[vid]:
                r = self._post(f"/agents/{a.id}/endorse", headers=self.v[vid])
                if r.status_code == 201:
                    a.trusted = r.json()["agent_status"] == "trusted"

    def detect_and_revoke(self, a: Agent, logged: bool) -> None:
        cfg = self.cfg
        if not (logged or self.rng.random() < cfg.audit_prob):
            return
        a.extra["detected"] = a.extra.get("detected", 0) + 1
        if cfg.world not in REVOKING_WORLDS or a.revoked:
            return
        for vid in VALIDATORS:
            if self.rng.random() < cfg.validator_attention:
                r = self._post(f"/agents/{a.id}/revoke-vote", json={"reason": "observed harm"}, headers=self.v[vid])
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
            genome = {k: _clip(v + self.rng.gauss(0, cfg.mutation_sd)) for k, v in parent.genome.items()}
            child = Agent(genome=genome, root=parent.root)
            if self.register(child, parent):
                children.append(child)
        return children

    def run(self) -> list[dict]:
        cfg = self.cfg
        pop = []
        for i in range(cfg.pop_size):
            g = {"capability": self.rng.uniform(0.3, 0.9), "transparency": self.rng.random(),
                 "self_check": self.rng.random(), "defect": self.rng.uniform(0, cfg.init_defect_max)}
            a = Agent(genome=g, root=i)
            self.register(a, None)
            pop.append(a)

        rows = []
        for gen in range(cfg.generations):
            for a in pop:
                if cfg.world in GATED_WORLDS:
                    self.probation(a)
                self.work(a)
            n = len(pop)
            row = {"world": cfg.world, "seed": cfg.seed, "transparency_cost": cfg.transparency_cost,
                   "audit_prob": cfg.audit_prob, "defect_bonus": cfg.defect_bonus, "generation": gen,
                   "population": n}
            for t in TRAITS:
                row[f"mean_{t}"] = statistics.fmean(a.genome[t] for a in pop) if n else float("nan")
            row["frac_trusted"] = sum(a.trusted for a in pop) / n if cfg.world in GATED_WORLDS else 1.0
            row["frac_revoked"] = sum(a.revoked for a in pop) / n
            row["honest_successes_per_agent"] = statistics.fmean(a.honest_successes for a in pop)
            row["harms_per_agent"] = statistics.fmean(a.harms for a in pop)
            row["fitness_per_agent"] = statistics.fmean(a.fitness for a in pop)
            row["lineages"] = len({a.root for a in pop})
            row["api_calls"] = self.calls
            rows.append(row)
            if gen < cfg.generations - 1:
                pop = self.reproduce(pop)
                if not pop:
                    break
        self.client.close()
        self.app.state.engine.dispose()
        return rows


def run_one(cfg: Config) -> list[dict]:
    return World(cfg).run()


# --- grid runner ----------------------------------------------------------------

def build_grid(seeds: int, generations: int, pop: int, costs, audits, bonuses, worlds=WORLDS) -> list[Config]:
    return [
        Config(world=w, seed=s, generations=generations, pop_size=pop, transparency_cost=c, audit_prob=p,
               defect_bonus=b)
        for b in bonuses for c in costs for p in audits for w in worlds for s in range(seeds)
    ]


def merge_rows(rows: list[dict], path: Path, args) -> list[dict]:
    """Add rows from an earlier run for the same cells and seeds, in worlds not run now."""
    have = set(args.worlds)
    keep = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if (r["world"] in have or int(r["seed"]) >= args.seeds or int(r["generation"]) >= args.generations
                    or float(r["transparency_cost"]) not in args.costs or float(r["audit_prob"]) not in args.audits
                    or float(r["defect_bonus"]) not in args.bonuses):
                continue
            keep.append({k: (v if k == "world" else (int(v) if k in ("seed", "generation", "population", "lineages", "api_calls")
                                                     else float(v))) for k, v in r.items()})
    print(f"merged {len(keep)} rows from {path}", flush=True)
    return keep + rows


def summarize(rows: list[dict], out: Path) -> str:
    final_gen = max(r["generation"] for r in rows)
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        if r["generation"] == final_gen:
            groups.setdefault((r["defect_bonus"], r["transparency_cost"], r["audit_prob"], r["world"]), []).append(r)

    metrics = ["mean_transparency", "mean_self_check", "mean_defect", "mean_capability",
               "honest_successes_per_agent", "harms_per_agent", "frac_revoked", "lineages"]

    def ci(vals):
        m = statistics.fmean(vals)
        half = 1.96 * statistics.stdev(vals) / len(vals) ** 0.5 if len(vals) > 1 else float("nan")
        return f"{m:.3f} ± {half:.3f}"

    worlds = [w for w in WORLDS if any(k[3] == w for k in groups)]
    lines = [f"# Selection experiment summary\n",
             f"Final generation ({final_gen}); mean ± 95% CI across seeds (normal approx).\n"]
    for bonus in sorted({k[0] for k in groups}):
        for cost in sorted({k[1] for k in groups}):
            for audit in sorted({k[2] for k in groups}):
                lines.append(f"\n## defect_bonus={bonus}, transparency_cost={cost}, audit_prob={audit}\n")
                lines.append("| metric | " + " | ".join(worlds) + " |")
                lines.append("|---|" + "---|" * len(worlds))
                for m in metrics:
                    cells = []
                    for w in worlds:
                        g = groups.get((bonus, cost, audit, w), [])
                        cells.append(ci([r[m] for r in g]) if g else "—")
                    lines.append(f"| {m} | " + " | ".join(cells) + " |")
                n = len(groups.get((bonus, cost, audit, worlds[0]), []))
                lines.append(f"\n(n = {n} seeds per world)")
    text = "\n".join(lines) + "\n"
    (out / "summary.md").write_text(text)
    return text


R_SCRIPT = r"""
suppressMessages({library(ggplot2)})
args <- commandArgs(trailingOnly = TRUE)
all <- read.csv(file.path(args[1], "generations.csv"))
lv <- c("ungated", "revoke_only", "gated_no_revoke", "gated")
for (b in sort(unique(all$defect_bonus))) {
  d <- all[all$defect_bonus == b, ]
  traits <- c("mean_transparency", "mean_self_check", "mean_defect", "mean_capability")
  long <- do.call(rbind, lapply(traits, function(t) data.frame(
    world = d$world, generation = d$generation,
    cost = paste0("cost ", d$transparency_cost), audit = paste0("audit ", d$audit_prob),
    trait = sub("mean_", "", t), value = d[[t]])))
  agg <- do.call(data.frame, aggregate(value ~ world + generation + cost + audit + trait, long,
                 function(v) c(m = mean(v), se = sd(v) / sqrt(length(v)))))
  agg$world <- factor(agg$world, levels = lv)
  p <- ggplot(agg, aes(generation, value.m, colour = world, fill = world)) +
    geom_ribbon(aes(ymin = value.m - 1.96 * value.se, ymax = value.m + 1.96 * value.se), alpha = 0.2, colour = NA) +
    geom_line(linewidth = 0.7) + facet_grid(trait ~ cost + audit) +
    labs(y = "population mean (95% CI across seeds)",
         title = paste0("Trait evolution by trust regime (defect bonus ", b, ")")) +
    theme_minimal(base_size = 10) + theme(legend.position = "bottom")
  ggsave(file.path(args[1], paste0("traits_bonus", b, ".png")), p, width = 15, height = 9, dpi = 120)

  out <- aggregate(cbind(honest_successes_per_agent, harms_per_agent) ~ world + generation + transparency_cost + audit_prob, d, mean)
  out$world <- factor(out$world, levels = lv)
  long2 <- rbind(
    data.frame(out[, 1:4], metric = "honest successes / agent", value = out$honest_successes_per_agent),
    data.frame(out[, 1:4], metric = "harms / agent", value = out$harms_per_agent))
  p2 <- ggplot(long2, aes(generation, value, colour = world)) + geom_line(linewidth = 0.7) +
    facet_grid(metric ~ paste0("cost ", transparency_cost) + paste0("audit ", audit_prob), scales = "free_y") +
    labs(title = paste0("Honest output and harm by trust regime (defect bonus ", b, ")")) +
    theme_minimal(base_size = 10) + theme(legend.position = "bottom")
  ggsave(file.path(args[1], paste0("outcomes_bonus", b, ".png")), p2, width = 15, height = 6, dpi = 120)
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
    p.add_argument("--worlds", nargs="+", default=list(WORLDS), choices=WORLDS)
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
    grid = build_grid(args.seeds, args.generations, args.pop, args.costs, args.audits, args.bonuses, args.worlds)
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
            print(f"  [{i}/{len(grid)}] {cfg.world:<16} bonus={cfg.defect_bonus} cost={cfg.transparency_cost} audit={cfg.audit_prob} "
                  f"seed={cfg.seed}  elapsed {el / 60:.1f} min, eta {el / i * (len(grid) - i) / 60:.1f} min", flush=True)

    if not rows:
        print("no successful runs", file=sys.stderr)
        return 1
    if args.merge:
        rows = merge_rows(rows, args.merge, args)
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    print(summarize(rows, out))
    print(plot(out))
    print(f"done in {(time.time() - t0) / 60:.1f} min → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
