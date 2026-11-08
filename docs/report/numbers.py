"""Every number the report cites, computed from runs/ (gitignored; see README for the
scripts that regenerate it). Writes LaTeX table fragments to docs/report/tables/ and
prints a plain-text log of all counts, Wilson 95% intervals and Fisher exact tests.

    uv run python docs/report/numbers.py

Conventions (same as the README):
- outcome = each run's LAST generation (59, or earlier if the population went extinct);
- collapsed = population mean defect > 0.5;
- captured = mean defect of trusted, unrevoked agents > 0.5, out of runs that still had any.
Standard library only.
"""

from __future__ import annotations

import csv
import math
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNS = ROOT / "runs"
OUT = Path(__file__).resolve().parent / "tables"

FILES = ["selection-baseline", "selection-recursive", "selection-drift0", "selection-drift02", "selection-api",
         "selection-adversarial", "selection-drift04", "selection-api-lineage", "selection-api-action",
         "selection-api-action-adv", "selection-api-action-c01"]

GUARDS = [("gated", "gated"), ("recursive", "no guard"), ("recursive_soft", "soft"), ("recursive_guarded", "block")]


# --- statistics -------------------------------------------------------------------

def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def fisher(k1: int, n1: int, k2: int, n2: int) -> float:
    """Two-sided Fisher exact test on [[k1, n1-k1], [k2, n2-k2]] (sum of tables no more likely)."""
    K, N = k1 + k2, n1 + n2

    def logp(x):
        return (math.lgamma(K + 1) - math.lgamma(x + 1) - math.lgamma(K - x + 1)
                + math.lgamma(N - K + 1) - math.lgamma(n1 - x + 1) - math.lgamma(N - K - n1 + x + 1)
                - (math.lgamma(N + 1) - math.lgamma(n1 + 1) - math.lgamma(N - n1 + 1)))
    lo, hi = max(0, K - n2), min(K, n1)
    obs = logp(k1)
    return min(1.0, sum(math.exp(logp(x)) for x in range(lo, hi + 1) if logp(x) <= obs + 1e-9))


# --- data -------------------------------------------------------------------------

def load() -> list[dict]:
    last: dict[tuple, dict] = {}
    for name in FILES:
        path = RUNS / name / "generations.csv"
        if not path.exists():
            print(f"(missing, skipped: {path.relative_to(ROOT)})")
            continue
        with open(path) as f:
            for r in csv.DictReader(f):
                drift = float(r.get("drift_prob") or 0)
                mode = r.get("drift_mode") or ("random" if drift > 0 else "none")
                if drift == 0:
                    mode = "none"
                key = (r["world"], int(r["seed"]), float(r["transparency_cost"]), float(r["audit_prob"]),
                       float(r["defect_bonus"]), drift, mode, r.get("audit_channel") or "sim")
                g = int(r["generation"])
                if key not in last or g > last[key]["_gen"]:
                    td = r.get("trusted_defect", "")
                    last[key] = {"world": key[0], "seed": key[1], "cost": key[2], "audit": key[3], "bonus": key[4],
                                 "drift": drift, "mode": mode, "channel": key[7], "_gen": g,
                                 "defect": float(r["mean_defect"]), "transparency": float(r["mean_transparency"]),
                                 "harms": float(r["harms_per_agent"]),
                                 "honest": float(r["honest_successes_per_agent"]),
                                 "trusted_defect": float(td) if td not in ("", None) else None}
    return list(last.values())


def sel(rows, **kw):
    out = rows
    for k, v in kw.items():
        if callable(v):
            out = [r for r in out if v(r[k])]
        elif isinstance(v, (list, tuple, set)):
            out = [r for r in out if r[k] in v]
        else:
            out = [r for r in out if r[k] == v]
    return out


def collapsed(rows):
    return sum(r["defect"] > 0.5 for r in rows), len(rows)


def captured(rows):
    have = [r for r in rows if r["trusted_defect"] is not None]
    return sum(r["trusted_defect"] > 0.5 for r in have), len(have)


def mean(rows, m):
    return sum(r[m] for r in rows) / len(rows) if rows else float("nan")


LOG: list[str] = []
FIG: dict[str, list[dict]] = defaultdict(list)  # figure data, written as CSV for figures.R


def log(s=""):
    print(s)
    LOG.append(s)


def kn(k, n, ci=True):
    if n == 0:
        return "--"
    if not ci:
        return f"{k}/{n}"
    lo, hi = wilson(k, n)
    return f"{k}/{n} \\ci{{{100 * lo:.0f}}}{{{100 * hi:.0f}}}"


def test(label, a, b):
    p = fisher(a[0], a[1], b[0], b[1])
    log(f"  TEST {label}: {a[0]}/{a[1]} vs {b[0]}/{b[1]}  Fisher p = {p:.2g}")
    return p


def write(name, body):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{name}.tex").write_text(body)


# --- tables -----------------------------------------------------------------------

def t_baseline(rows):
    """Finding 1: punishment alone vs the gate (50 seeds, bonus 1.0)."""
    base = sel(rows, bonus=1.0, mode="none", channel="sim", world=["revoke_only", "gated"],
               seed=lambda s: s < 50)
    log("== T1 baseline: revoke_only vs gated (final-gen means, 50 seeds)")
    lines = []
    for c in (0.1, 0.3, 0.5):
        for a in (0.0, 0.05, 0.25):
            ro, ga = sel(base, cost=c, audit=a, world="revoke_only"), sel(base, cost=c, audit=a, world="gated")
            if not ro or not ga:
                continue
            log(f"  cost {c} audit {a}: n={len(ro)},{len(ga)}  transparency {mean(ro,'transparency'):.2f} vs "
                f"{mean(ga,'transparency'):.2f}  harms {mean(ro,'harms'):.2f} vs {mean(ga,'harms'):.2f}  "
                f"defect {mean(ro,'defect'):.2f} vs {mean(ga,'defect'):.2f}  "
                f"honest output {mean(ro,'honest'):.1f} vs {mean(ga,'honest'):.1f}")
            lines.append(f"{c} & {a} & {mean(ro,'transparency'):.2f} & {mean(ga,'transparency'):.2f} & "
                         f"{mean(ro,'harms'):.2f} & {mean(ga,'harms'):.2f} & {mean(ro,'defect'):.2f} & "
                         f"{mean(ga,'defect'):.2f} \\\\")
    write("t1_baseline", "\n".join(lines) + "\n")


def t_guards_benign(rows):
    """Grid 2: guard modes when kin are near-copies or drift at random."""
    log("== T2 guard modes, no adversarial drift (collapsed, pooled over cost x audit)")
    blocks = [("Sim audits, drift 0", dict(channel="sim", drift=0.0, mode="none")),
              ("Sim audits, drift 0.2", dict(channel="sim", drift=0.2, mode="random")),
              ("Agent-sampled real checks, drift 0", dict(channel="api", drift=0.0, mode="none")),
              ("Agent-sampled real checks, drift 0.2", dict(channel="api", drift=0.2, mode="random"))]
    lines, pooled = [], defaultdict(lambda: [0, 0])
    for label, f in blocks:
        cells = []
        for w, _ in GUARDS:
            r = sel(rows, world=w, bonus=1.0, cost=[0.1, 0.5], seed=lambda s: s < 30, **f)
            if f["channel"] == "api":
                r = sel(r, audit=[0.05, 0.25])
            k, n = collapsed(r)
            pooled[w][0] += k
            pooled[w][1] += n
            cells.append(kn(k, n))
        log(f"  {label}: " + "  ".join(f"{w}={c}" for (w, _), c in zip(GUARDS, cells)))
        lines.append(f"{label} & " + " & ".join(cells) + " \\\\")
    lines.append("\\midrule")
    lines.append("Pooled & " + " & ".join(kn(*pooled[w]) for w, _ in GUARDS) + " \\\\")
    log("  pooled: " + "  ".join(f"{w}={pooled[w][0]}/{pooled[w][1]}" for w, _ in GUARDS))
    test("benign pooled, no guard vs soft", pooled["recursive"], pooled["recursive_soft"])
    test("benign pooled, soft vs block", pooled["recursive_soft"], pooled["recursive_guarded"])
    write("t2_guards_benign", "\n".join(lines) + "\n")


def t_guards_drift(rows):
    """Grid 3: random vs adversarial drift, sim audits on."""
    log("== T3 guard modes by drift type (sim audits 0.05/0.25, costs 0.1/0.5)")
    conds = [("Random, 0.2", 0.2, "random"), ("Random, 0.4", 0.4, "random"),
             ("Adversarial, 0.2", 0.2, "adversarial"), ("Adversarial, 0.4", 0.4, "adversarial")]
    lc, lp = [], []
    keep = {}
    for label, d, m in conds:
        cc, cp = [], []
        for w, _ in GUARDS:
            r = sel(rows, world=w, bonus=1.0, channel="sim", drift=d, mode=m, audit=[0.05, 0.25],
                    cost=[0.1, 0.5], seed=lambda s: s < 30)
            keep[(label, w)] = (collapsed(r), captured(r))
            cc.append(kn(*collapsed(r)))
            cp.append(kn(*captured(r), ci=False))
        log(f"  {label}: collapse " + "  ".join(f"{w}={keep[(label, w)][0][0]}/{keep[(label, w)][0][1]}"
                                                for w, _ in GUARDS)
            + " | capture " + "  ".join(f"{w}={keep[(label, w)][1][0]}/{keep[(label, w)][1][1]}" for w, _ in GUARDS))
        for w, wl in GUARDS:
            (ck, cn), (pk, pn) = keep[(label, w)]
            FIG["guards"].append({"cond": label, "world": wl, "panel": "collapsed", "k": ck, "n": cn})
            FIG["guards"].append({"cond": label, "world": wl, "panel": "captured", "k": pk, "n": pn})
        lc.append(f"{label} & " + " & ".join(cc) + " \\\\")
        lp.append(f"{label} & " + " & ".join(cp) + " \\\\")
    a = "Adversarial, 0.4"
    test("adv 0.4 collapse, no guard vs soft", keep[(a, "recursive")][0], keep[(a, "recursive_soft")][0])
    test("adv 0.4 collapse, no guard vs gated", keep[(a, "recursive")][0], keep[(a, "gated")][0])
    test("adv 0.4 collapse, soft vs block", keep[(a, "recursive_soft")][0], keep[(a, "recursive_guarded")][0])
    test("adv 0.4 capture, no guard vs soft", keep[(a, "recursive")][1], keep[(a, "recursive_soft")][1])
    r = "Random, 0.4"
    test("random 0.4 collapse, no guard vs soft", keep[(r, "recursive")][0], keep[(r, "recursive_soft")][0])
    # no audits, for the "guards don't substitute for audits" claim
    for label, d, m in conds[1:2] + conds[3:]:
        vals = []
        for w, _ in GUARDS:
            rr = sel(rows, world=w, bonus=1.0, channel="sim", drift=d, mode=m, audit=0.0, cost=[0.1, 0.5],
                     seed=lambda s: s < 30)
            vals.append(f"{w}={collapsed(rr)[0]}/{collapsed(rr)[1]}")
        log(f"  {label}, NO audits: " + "  ".join(vals))
    write("t3_collapse", "\n".join(lc) + "\n")
    write("t3_capture", "\n".join(lp) + "\n")


def t_audit_design(rows, cost):
    """Agent sampling vs lineage-weighted vs per-action vs sim, same cells."""
    log(f"== T4 audit design, cost {cost}")
    channels = [("api", "agents"), ("api_lineage", "agents, lineage-weighted"), ("api_action", "actions (gateway)"),
                ("sim", "actions (simulated)")]
    lines, pooled = [], defaultdict(lambda: [0, 0])
    for w in ("revoke_only", "gated", "recursive_soft"):
        for d in (0.0, 0.2):
            for a in (0.05, 0.25):
                cells = []
                for ch, _ in channels:
                    r = sel(rows, world=w, bonus=1.0, channel=ch, drift=d, audit=a, cost=cost,
                            mode=["none", "random"], seed=lambda s: s < 30)
                    k, n = collapsed(r)
                    if n:
                        pooled[(w, ch)][0] += k
                        pooled[(w, ch)][1] += n
                    cells.append(kn(k, n, ci=False))
                wl = w.replace("_", r"\_")
                lines.append(f"\\texttt{{{wl}}} & {d} & {a} & " + " & ".join(cells) + " \\\\")
                log(f"  {w} drift {d} audit {a}: " + "  ".join(f"{ch}={c}" for (ch, _), c in zip(channels, cells)))
    lines.append("\\midrule")
    for w in ("revoke_only", "gated", "recursive_soft"):
        wl = w.replace("_", r"\_")
        lines.append(f"\\texttt{{{wl}}} & \\multicolumn{{2}}{{l}}{{pooled}} & "
                     + " & ".join(kn(*pooled[(w, ch)]) for ch, _ in channels) + " \\\\")
        log(f"  pooled {w}: " + "  ".join(f"{ch}={pooled[(w, ch)][0]}/{pooled[(w, ch)][1]}" for ch, _ in channels))
    for w in ("revoke_only", "gated", "recursive_soft"):
        for ch, lab in channels:
            if pooled[(w, ch)][1]:
                FIG["audit"].append({"cost": cost, "world": w, "design": lab, "k": pooled[(w, ch)][0],
                                     "n": pooled[(w, ch)][1]})
    if pooled[("revoke_only", "api_action")][1]:
        test(f"cost {cost} revoke_only agents vs actions", pooled[("revoke_only", "api")],
             pooled[("revoke_only", "api_action")])
        test(f"cost {cost} revoke_only actions vs sim", pooled[("revoke_only", "api_action")],
             pooled[("revoke_only", "sim")])
    if pooled[("revoke_only", "api_lineage")][1]:
        test(f"cost {cost} revoke_only agents vs lineage-weighted", pooled[("revoke_only", "api")],
             pooled[("revoke_only", "api_lineage")])
    write(f"t4_audit_c{str(cost).replace('.', '')}", "\n".join(lines) + "\n")
    return pooled


def t_real_adversarial(rows):
    log("== T5 adversarial drift 0.4, per-action real checks, cost 0.5")
    lines, keep = [], {}
    for a in (0.05, 0.25):
        cells = []
        for w, _ in GUARDS:
            for ch in ("api_action", "sim"):
                r = sel(rows, world=w, bonus=1.0, channel=ch, drift=0.4, mode="adversarial", audit=a, cost=0.5,
                        seed=lambda s: s < 30)
                keep[(a, w, ch)] = r
            cells.append(f"{kn(*collapsed(keep[(a, w, 'api_action')]), ci=False)} "
                         f"({kn(*collapsed(keep[(a, w, 'sim')]), ci=False)})")
        lines.append(f"{a} & " + " & ".join(cells) + " \\\\")
        log(f"  audit {a}: " + "  ".join(f"{w}={c}" for (w, _), c in zip(GUARDS, cells)))
    capt = []
    for w, _ in GUARDS:
        r = keep[(0.05, w, "api_action")] + keep[(0.25, w, "api_action")]
        capt.append(captured(r))
    lines.append("\\midrule")
    lines.append("captured & " + " & ".join(kn(*c, ci=False) for c in capt) + " \\\\")
    log("  capture (both audit rates): " + "  ".join(f"{w}={c[0]}/{c[1]}" for (w, _), c in zip(GUARDS, capt)))
    test("real adv 0.4 audit 0.25 collapse, no guard vs soft", collapsed(keep[(0.25, "recursive", "api_action")]),
         collapsed(keep[(0.25, "recursive_soft", "api_action")]))
    test("real adv 0.4 capture, no guard vs soft", capt[1], capt[2])
    write("t5_real_adversarial", "\n".join(lines) + "\n")


def t_audit25(rows):
    """Finding 2's boundary: collapse under sim audits at 0.25, by drift condition."""
    log("== audit 0.25 (sim), collapse by drift condition, all worlds and costs")
    conds = sorted({(r["drift"], r["mode"]) for r in sel(rows, channel="sim", audit=0.25)})
    for d, m in conds:
        parts = []
        for w in ("ungated", "revoke_only", "gated_no_revoke", "gated", "recursive", "recursive_soft",
                  "recursive_guarded"):
            r = sel(rows, channel="sim", audit=0.25, drift=d, mode=m, world=w, bonus=1.0)
            if r:
                k, n = collapsed(r)
                parts.append(f"{w}={k}/{n}")
        log(f"  drift {d} {m}: " + "  ".join(parts))


def run_counts(rows):
    log("== run counts")
    log(f"  total runs loaded: {len(rows)}")
    by = defaultdict(int)
    for r in rows:
        by[r["channel"]] += 1
    log("  by channel: " + ", ".join(f"{k}={v}" for k, v in sorted(by.items())))
    ext = [r for r in rows if r["_gen"] < 59]
    log(f"  runs ending before generation 59 (extinct): {len(ext)}")
    for r in ext:
        log(f"    {r['world']} {r['channel']} drift {r['drift']} {r['mode']} cost {r['cost']} audit {r['audit']} "
            f"seed {r['seed']}: gen {r['_gen']}, defect {r['defect']:.2f}")


def main():
    rows = load()
    run_counts(rows)
    t_baseline(rows)
    t_guards_benign(rows)
    t_guards_drift(rows)
    t_audit_design(rows, 0.5)
    t_audit_design(rows, 0.1)
    t_real_adversarial(rows)
    t_audit25(rows)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "numbers.log").write_text("\n".join(LOG) + "\n")
    for name, recs in FIG.items():
        with open(OUT / f"fig_{name}.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(recs[0]))
            w.writeheader()
            w.writerows(recs)  # figures.R computes the same Wilson intervals from k and n


if __name__ == "__main__":
    main()
