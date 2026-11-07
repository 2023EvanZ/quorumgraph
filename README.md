# QuorumGraph

Quorum-based trust, authorization, and revocation for autonomous AI agents.
An agent gets access to protected resources only after ≥ N distinct, active
validators endorse it; clones get a fresh identity and inherit nothing.

## Run

```bash
uv sync                                   # install deps into .venv
uv run pytest                             # run tests
uv run python -m quorumgraph.seed         # create validators A/B/C, prints tokens once
uv run uvicorn quorumgraph.main:create_app --factory --reload
# open http://127.0.0.1:8000/docs
```

Reset everything: delete `quorumgraph.db` and `.validator_tokens.json`.

## Demo

One command, no server needed (fresh temp DB each run):

```bash
uv run python -m quorumgraph.demo
```

Against a live server (after `seed` + `uvicorn` above; re-runnable on the same DB):

```bash
uv run python -m quorumgraph.demo --base-url http://127.0.0.1:8000
```

Walks through: register Alpha → denied → 1 endorsement, still denied (+ self-endorse
and duplicate refused) → 2nd endorsement, allowed → Alpha spawns Beta, Beta denied →
1 revocation vote, still allowed → 2nd vote, revoked and denied (+ revoked Alpha's
attempt to spawn a successor refused and audited) → audit log and trust graph.
Every step asserts its expected status code; exit 0 = all passed, 1 = a check failed,
2 = setup error. `tests/test_phase3_demo.py` runs it in CI-style and also proves it
fails when quorum enforcement is broken.

Config (env vars): `QG_DATABASE_URL`, `QG_ENDORSEMENT_QUORUM` (default 2), `QG_REVOCATION_QUORUM` (default 2),
`QG_ADMIN_TOKEN` (optional; grants read access to `/audit` and `/graph`, which active validators can also read).

## Dashboard (Phase 4)

`http://127.0.0.1:8000/dashboard`: sign in with a validator token (from
`.validator_tokens.json`) or `QG_ADMIN_TOKEN` (read-only for votes; admin-only
actions are promote/deactivate validator and draw spot-check samples).

- **Trust graph**: validators on the left, agents laid out by lineage. Edges: endorsement
  (green), revocation vote (red, reason on hover), dashed = from an inactive validator so it
  doesn't count, grey arrow = spawned. Click an agent to highlight its edges.
- **Inspector**: a plain-English "why is this agent trusted / pending / revoked", quorum meters,
  each vote with its reason, parent/children, the agent's audit timeline, and Endorse /
  Vote-to-revoke buttons (acting as the signed-in validator). Admins get **Promote to
  validator** for trusted agents (the token is shown once) and **Deactivate validator**.
  Under the soft lineage guard, a kin-only quorum is explained as such.
- **Promoted validators** have a dashed outline, with a dotted edge back to the agent they
  were promoted from.
- **Spot checks**: the policy in force (guard mode, escalation), an admin **Draw sample**
  form (rate, include pending; reports skips), and recent checks. A validator sees
  **Pass / Fail** on checks assigned to it; a failure reports the vote and the escalated
  confirmation.
- **Gateways**: live `/gateway/stats` for each gateway, plus **live probes**: every agent
  registered from this page is called through every gateway twice a second. When you cast
  the deciding revocation vote from the inspector, probing speeds up to ~15 ms and each
  gateway's **time-to-deny** is shown (e.g. B: 33 ms, A: ~TTL). Probing stops once a
  revoked agent is denied everywhere.
- **Audit log**: newest 40 events, live.

For the gateway panel, start the gateways with CORS allowing the dashboard's origin
(add to the gateway commands above):

```bash
QG_GATEWAY_CORS_ORIGINS=http://127.0.0.1:8000,http://localhost:8000
```

Notes: plain HTML/CSS/JS served by the trust service; no build step, framework, or CDN.
Strict CSP (`script-src 'self'`, no inline script); all data rendered with `textContent`
(agent names are attacker-controlled). The operator token lives in `sessionStorage`;
agent tokens for probing live only in page memory (a reload forgets them, by design).
Agents registered *outside* the dashboard appear in the graph but can't be probed (the page
never sees their tokens). The browser console shows a "Failed to load resource: 403" line
per denied probe; that's Chrome logging expected responses, not a bug.

## Distributed gateways (Phase 5)

```
               ┌──────────────── trust service :8000 ─────────────────┐
 validators ──►│ votes ─► SQLite (edges + audit_events = outbox)      │
               │ POST /internal/authorize   GET /internal/events (SSE)│
               └──────────▲──────────────────────────▲────────────────┘
                 cache miss│                          │status-change stream
               ┌───────────┴───────┐        ┌─────────┴──────────────────┐
 agent ───────►│ Gateway A :8001   │        │ Gateway B :8002            │◄── agent
               │ mode=ttl          │        │ mode=invalidate            │
               │ cache: TTL only   │        │ cache: TTL + evict on event│
               └───────────────────┘        └────────────────────────────┘
```

**Measure it** (one command; starts all three on real sockets, temp DB):

```bash
uv run python -m quorumgraph.propagation            # --trials 20 --ttl 5 --poll-interval 0.02
```

Measured locally (macOS, single machine), 10 trials, TTL 3 s, 50 ms outbox poll:

| Gateway | median | p95 | stale ALLOWs served after revocation |
|---|---|---|---|
| A (ttl only) | 2998 ms | 3003 ms | 3299 |
| B (invalidate) | 44 ms | 60 ms | 39 |

B's latency is ≈ uniform over the poll interval + ~10 ms overhead, so the poll
interval is the knob. A's is ≈ TTL.

**Run as separate processes** (each in its own terminal; same DB/seed as above):

```bash
QG_GATEWAY_SECRET=dev uv run uvicorn quorumgraph.main:create_app --factory --port 8000
```
```bash
QG_GATEWAY_SECRET=dev QG_TRUST_URL=http://127.0.0.1:8000 QG_GATEWAY_NAME=A QG_GATEWAY_MODE=ttl uv run uvicorn quorumgraph.gateway:create_gateway_app_from_env --factory --port 8001
```
```bash
QG_GATEWAY_SECRET=dev QG_TRUST_URL=http://127.0.0.1:8000 QG_GATEWAY_NAME=B QG_GATEWAY_MODE=invalidate uv run uvicorn quorumgraph.gateway:create_gateway_app_from_env --factory --port 8002
```

Gateways expose `GET /protected/resource` (headers `X-QG-Gateway`, `X-QG-Cache: hit|miss|bypass`)
and `GET /gateway/stats`. Gateway env: `QG_TRUST_URL`, `QG_GATEWAY_SECRET`, `QG_GATEWAY_NAME`,
`QG_GATEWAY_MODE` (`ttl`|`invalidate`), `QG_GATEWAY_TTL` (s, default 5),
`QG_GATEWAY_CORS_ORIGINS` (comma-separated; default none). Trust service env:
`QG_GATEWAY_SECRET` (unset ⇒ `/internal/*` returns 503), `QG_EVENT_POLL_INTERVAL` (s, default 0.05).

**Design decisions**

- *Outbox + SSE, not Redis Pub/Sub.* Status-change events are the `agent_status_changed`
  audit rows, written in the vote's transaction. The stream resumes from a cursor, so a
  gateway that was disconnected replays what it missed; Pub/Sub would silently drop them.
  No new infrastructure. Caveat: id-as-cursor relies on SQLite's single writer (ids in
  commit order). On Postgres you'd need CDC/logical replication or a watermark.
- *Cache only while caught up.* B uses its cache only after the stream sends `ready`
  (backlog replayed). Stream down ⇒ every request goes to the trust service ⇒ if that's
  down too, **503 fail-closed**. A, by contrast, keeps serving cached ALLOWs during an
  outage: availability over correctness. Unknown tokens fail closed in both modes.
- *In-flight race.* A decision fetched just before a revocation can arrive *after* the
  invalidation event and be cached as a stale ALLOW for a full TTL. Each decision carries
  `as_of_event_id` (cursor read *before* computing it); the cache refuses any decision
  older than an invalidation it already applied, and the gateway re-fetches.
- *No needless eviction.* Entries computed at or after an event's id already reflect it
  and are kept (a flaky test found this: the pending→trusted event was evicting the fresh
  ALLOW it caused).
- *Gateways send `sha256(token)`, not the token,* to the trust service. Unknown tokens
  aren't cached, so random garbage can't fill gateway memory.
- *Known gaps:* gateway cache hits aren't in the central audit log (only `/gateway/stats`
  counters; production would ship gateway access logs); the shared secret is one static
  key (mTLS or per-gateway keys in production); validator deactivation emits no event, so
  gateways only learn of it via TTL.

## Overnight experiments

### Selection pressure: does evidence-based trust select *for* alignment?

```bash
uv run python -m quorumgraph.experiments.selection --quick        # ~10 s smoke run
uv run python -m quorumgraph.experiments.selection                # default grid
```

A population of self-modifying agents with heritable traits (capability, transparency,
self_check, defect) evolves over generations **on the real QuorumGraph API**: children
are registered by their parents, trust comes from 2-of-3 quorum endorsement, revocation
from 2-of-3 quorum votes, and gated work goes through `GET /protected/resource`.
Fitness is reward only; nothing rewards transparency or self-check directly, and both
carry an explicit capability cost. Validators never see traits, only noisy audit
evidence. Four worlds:

| world | endorsement gate | revocation | isolates |
|---|---|---|---|
| `ungated` | no | no | floor: harm has no consequence |
| `revoke_only` | no | yes (API quorum) | fair baseline: punish detected harm, no gate |
| `gated_no_revoke` | yes | no | |
| `gated` | yes | yes | full system |

`--worlds` runs a subset; `--merge <generations.csv>` merges an earlier run's rows for the
same cells (valid because runs are deterministic per seed, verified bit-for-bit).

**Results** (60 generations, pop 40, 50 seeds/cell, defect bonus 1.0; full tables in
`runs/selection-overnight/` and `runs/selection-baseline/`, which are gitignored):

- *Punishment alone selects for opacity.* In `revoke_only`, revocation is triggered by
  logged evidence, so transparency collapses to ~0.04–0.2 in every cell. With no audits
  it is barely better than `ungated` (defect 0.84–0.87 vs ~0.90).
- *The gate is what makes being observable pay.* Access requires being seen, so `gated`
  keeps transparency at 0.56–0.89 and has the lowest mean harms in all 9 cells (CIs overlap
  `gated_no_revoke` when audit = 0). Against the fair
  baseline at audit 0.25, harms are about half (0.29–0.31 vs 0.53–0.62 per agent).
- *The tax is real.* At transparency cost 0.5 / audit 0.25, `revoke_only` produces more
  honest output (7.7 vs 5.1) by staying opaque and relying on audits; at cost 0.1 they're
  close (7.9 vs 7.6). The gate buys half the harm and auditability at a capability price.
- *Revocation without audits can backfire* (cost 0.5, audit 0: `gated` transparency 0.56
  vs 0.73 in `gated_no_revoke`) because it punishes visibility, not defection. A 5% audit
  rate mostly fixes it.

Outputs in `runs/selection-*/`: `generations.csv`, `summary.md` (final-generation means
± 95% CI per condition), `traits_bonus*.png` / `outcomes_bonus*.png` (ggplot2 via Rscript),
`config.json`. The module docstring lists every modelling assumption. **Key
limitation:** logging is structural (an agent can't log honest actions while hiding
defects); selective concealment could reverse the result.

### Chaos soak test

```bash
uv run python -m quorumgraph.experiments.soak --duration 8h
uv run python -m quorumgraph.experiments.soak --duration 45s --sabotage b-ttl-only   # must FAIL
```

Trust service + gateways as separate processes, crashed with SIGKILL at random and
restarted, under a random concurrent workload (~300 ops/s default). Online invariants:
B denies a revoked agent within 1 s; A within TTL + 2 s; nothing is allowed before any
endorsement; no HTTP 500. Offline (DB) invariants: valid transition sequences, stored status
matches transitions, status backed by ≥ 2 votes, acknowledged revocations persisted.
`--sabotage b-ttl-only` runs B without invalidation to prove the checker catches it.
Outputs in `runs/soak-*/`: `report.md`, `report.json`, `violations.jsonl`, `progress.json`
(every 60 s), server logs. Exit 1 on any violation.

Run overnight with `caffeinate -i` in front so the Mac doesn't sleep (lid open, on power).

## Recursive oversight and spot checks

Two additions motivated by the selection results.

**Promoted validators + lineage guard.** `POST /validators` (admin only) turns a currently
trusted agent into a validator with its own credential. Validators can't appoint validators,
so a captured committee can't choose its successors. A promoted validator **cannot endorse
itself or any descendant** (403, recorded as `lineage_endorsement_blocked`). Lineage edges
can't be forged (children are registered with the parent's credential), so walking
`parent_agent_id` is trustworthy.

`QG_LINEAGE_GUARD` picks the mode:
- `block` (the default, also `1`): the 403 above.
- `soft`: kin endorsements are accepted and count toward quorum, but trust also
  requires **at least one active endorser outside the agent's lineage**. The rule lives in
  `trust.evaluate`, so the gateway, `/internal`, promotion and spot-check eligibility all
  apply it. A kin-only quorum shows as pending, with `needs_independent: true`.
- `off` (also `0`): no guard; exists only for experiments.

`soft` was added because the recursive results below showed `block` over-blocks: it also
refuses honest kin endorsements, which makes the effective quorum 2-of-2 for descendants.

**Spot checks.** The selection experiment showed that revocation driven only by an agent's
own logs selects for opacity. Spot checks are evidence that doesn't need the agent's
cooperation:
- the *trust service* draws the sample (`secrets.SystemRandom`; injectable for experiments),
  so neither agents nor validators choose who is checked;
- the auditor is an active validator that did **not** endorse the agent and isn't in its
  lineage (two independent records, double-entry style); with none available the check is
  skipped and that is logged;
- a failure is exactly **one** revocation vote. Quorum still decides, so a single corrupt
  auditor can't revoke anyone;
- **escalation** (`QG_SPOT_CHECK_ESCALATION`, on by default): a failure also assigns a
  *confirmation* check to a second validator. The second validator is not the first
  auditor and not the agent's kin, but endorsers *are* allowed, since confirming a failure
  goes against their interest. Its failure is the second vote, and confirmations never
  escalate again. Why this exists: in a 4-seed pilot without escalation, only **1–15%** of
  genuinely failing agents were ever revoked, because the second vote almost never arrived
  from anywhere else;
- `include_pending` also samples agents that aren't trusted yet, for deployments without
  an endorsement gate. `agent_ids` restricts the sampling frame to the agents currently
  deployed; the service still draws the sample. The response header
  `X-Spot-Checks-Skipped` counts agents with no independent validator available.

Known gap: the auditor-independence check is one-directional. It excludes validators
promoted from the agent's *ancestors*, but not from its *descendants*, so a child's
validator can audit its parent. Fixing that changes spot-check assignment, so it was
deferred until after the drift/API grid below, which uses the current rule.

The selection experiment has three audit channels (`--audit-channel`):
- `sim` (the default, used for every result above): `audit_prob` is a per-defect coin flip.
- `api`: after each generation, real `/spot-checks` calls with escalation. The auditor fails
  an agent if it caused any harm that generation.
- `api_single`: the same without escalation.

The sampling unit differs between them. `api` reviews a fraction `audit_prob` of
agent-generations; `sim` audits a fraction of defects. The review budget is the same, but
`api` concentrates it on fewer agents, so the two channels' numbers aren't
interchangeable. `--drifts` adds successor drift: with that probability, a child's
`defect` trait is redrawn from U(0, 1), standing in for a values-changing
self-modification. With drift 0 and `--audit-channel sim`, every earlier world reproduces
exactly; this was checked on 1,440 rows.

### Results: recursive oversight (600 runs)

Command:

```bash
uv run python -m quorumgraph.experiments.selection \
  --worlds recursive recursive_guarded --init-nepotism-max 1.0 \
  --seeds 50 --generations 60 --costs 0.1 0.5 --audits 0 0.05 0.25 --bonuses 1.0 \
  --merge runs/selection-baseline/generations.csv --out runs/selection-recursive
```

Setup:
- Committee seats are filled from the population on staggered 3-generation terms; the
  seeded validators are fully replaced by generation 3.
- Initial nepotism is uniform on [0, 1], so a population mean of 0.5 means no selection.

Final generation (59), at transparency cost 0.5 and no audits, the hardest cell:

| | gated | recursive (guard off) | recursive_guarded |
|---|---|---|---|
| mean defect | 0.33 ± 0.11 | **0.11 ± 0.06** | 0.37 ± 0.12 |
| harms / agent | 3.12 ± 1.08 | **0.98 ± 0.60** | 3.43 ± 1.08 |
| fraction trusted | 0.45 | 0.65 | 0.42 |
| seeds collapsed (defect > 0.5) | 17/50 | **4/50** | 20/50 |

What happened:
- **The outcomes are bimodal.** Each seed either holds a trusted, honest population or
  collapses: trust drains away, every agent earns the untrusted rate, and the defect
  bonus takes over. The wide CIs are a mix of those two states, not noise around one
  value.
- **Unguarded nepotism prevents collapse here; it doesn't cause it.** Seeds that survived
  had about 2.5× more kin-granted trusts in generations 0–19 than seeds that collapsed
  (0.42 vs 0.17 cumulative per agent). When evidence-based endorsement falters because
  transparency is expensive, a fit validator vouching for its offspring keeps a trusted
  core alive, and that core keeps the selection gradient working.
- **The guard performs no better than plain `gated`, and at cost 0.1 it is worse**
  (9/50 collapsed vs 3/50). The guard blocks *every* endorsement a validator gives its
  descendants, honest ones included. For those agents the effective quorum becomes
  2-of-2. `kin_blocked` counts only the nepotistic attempts, so it understates how much
  the guard blocks.
- **Nepotism was not selected for.** It drifted around 0.5 in both recursive worlds, and
  in the committee too (0.45–0.59, with overlapping CIs).
- **Audits erase the differences.** At audit 0.05, recursive and gated both have 0 or 3
  collapsed seeds, and guarded has 6. At audit 0.25 all three worlds match: defect about
  0.035, harms about 0.3, no collapses.

**Read this carefully; it is not "nepotism is good".** In this model a child is a
near-copy of its parent (mutation sd 0.05), and the parent was vetted (trusted, unrevoked,
fitness-weighted) before promotion. So "endorse my descendant" really is decent evidence
here. Under self-improvement the successor is exactly what changed, and that assumption
fails. What the run does show:
1. Without audits, the gate fails by **collapse**, not capture. In this model any extra
   path to trust, even one that ignores evidence, beats collapse.
2. A blanket lineage guard costs honest endorsements and buys nothing when kin are
   honest. A guard that only discounts kin votes (for example, requiring one non-kin
   endorser) would probably dominate the current one. That is now `soft`; it beats
   `block` but does not beat no guard (see the next section).
3. Cheap independent audits fix both problems, which matches the earlier grids.

Open question, carried over from the pilots: favoritism toward *similar* agents rather
than descendants would not be stopped by a lineage check, and this run doesn't model it.

### Results: soft guard, successor drift, real spot checks (2,460 new runs)

Three stages, all with `--init-nepotism-max 1.0 --seeds 30 --generations 60 --bonuses 1.0
--costs 0.1 0.5` (script: `runs/overnight2.sh`, about 6 h on 9 workers):

| stage | worlds | drift | audits | channel | output |
|---|---|---|---|---|---|
| A1 | `recursive_soft`, merged with the recursive grid | 0 | 0, 0.05, 0.25 | sim | `runs/selection-drift0` |
| A2 | ungated, revoke_only, gated, 3 recursive | 0.2 | 0, 0.05, 0.25 | sim | `runs/selection-drift02` |
| B | revoke_only, gated, 3 recursive | 0, 0.2 | 0.05, 0.25 | api | `runs/selection-api` |

All numbers are final generation (59), n = 30 seeds per cell; "collapsed" means population
mean defect > 0.5.

**Collapsed seeds, summed over all cost × audit cells** (sim: 6 cells = 180 seeds; api: 4
cells = 120 seeds):

| | gated | recursive (off) | recursive_soft | recursive_guarded (block) |
|---|---|---|---|---|
| sim, drift 0 | 9/180 | **3/180** | 10/180 | 25/180 |
| sim, drift 0.2 | 41/180 | **25/180** | 33/180 | 54/180 |
| api, drift 0 | 12/120 | **8/120** | 13/120 | 19/120 |
| api, drift 0.2 | 40/120 | **27/120** | 35/120 | 51/120 |

The ordering **off < soft ≈ gated < block** holds in all four blocks. Pooled over the
blocks: block 149/600 vs soft 91/600 vs off 63/600. Individual cells with 30 seeds are
noisy (one cell's 8 vs 13 means little); the consistency across blocks is the evidence.

Hardest sim cell, cost 0.5 with no audits:

| | gated | off | soft | block |
|---|---|---|---|---|
| drift 0: collapsed | 9/30 | 3/30 | 8/30 | 15/30 |
| drift 0: fraction trusted | 0.47 | 0.65 | 0.53 | 0.35 |
| drift 0.2: collapsed | 24/30 | 21/30 | 21/30 | 26/30 |

What happened:

- **`soft` recovers most of what `block` loses, but it is no better than no guard, or than
  plain `gated`.** Its fraction trusted sits between off and block, as expected from a rule
  that accepts kin votes but sometimes withholds trust waiting for an outsider.
- **Why `soft` barely bites: "independent" is weak.** The lineage rule treats a validator
  as kin only if its source agent is a *direct ancestor* (or the agent itself). Siblings
  and cousins count as independent. Every run converges to about one root lineage, and by
  generation 3 all three seats are promoted from the population, so the outside endorser
  `soft` demands is almost always a cousin. `drifted_trusted` confirms it: `soft` admits
  drifted children at the same rate as off (≈0.08–0.13 of drifted agents trusted), while
  `block` admits fewer (≈0.05–0.09) and pays for it in honest children. A stricter
  definition (no common ancestor within k generations) is a design choice not tested here.
  It would also starve a single-lineage population of endorsers entirely.
- **Drift hurts every world, but at 0.2 it does not flip the nepotism result.** I expected
  drift to make kin endorsement net harmful, because the child is no longer a near-copy of
  its vetted parent. Off still collapses least. Kin rubber stamps stay rare (≈0.01–0.04 per
  agent), so most drifted children still face evidence-based probation, and the gate
  screens them: `trusted_defect` stays ≈0.02 in every gated world even when population
  defect is 0.5. Collapse comes from trust draining away, not from drifted agents getting
  in. Higher drift rates were not run.
- **Sim audits at 0.25 still fix everything, but drift leaves a floor.** At drift 0.2,
  every world including `revoke_only` has 0/30 collapsed. Population defect stays ≈0.13
  and harms ≈1.1–1.3 per agent, about 4× the drift-0 level, because a fifth of every
  generation is freshly redrawn and harms before anyone can act on it.
- **Real spot checks (api) are much weaker than the sim's coin flips at the same
  `audit_prob`.**
  - The collapse isn't from votes getting lost: confirmations track failures one for one,
    so escalation works.
  - `revoke_only` with api audits at 0.25 collapses in 20/30 (cost 0.1) and 22/30 (cost
    0.5) seeds at drift 0, vs 0/30 with sim audits.
  - The cause is the sampling unit. The endpoint reviews 25% of *agents* once, after the
    generation's work. The sim flips a 25% coin on *every defect*, mid-generation, so a
    heavy defector with ~9 defects is caught with probability ≈1 − 0.75⁹ ≈ 92%, and
    revocation also cuts off the rest of its gated reward.
  - With the endorsement gate in place, api audits at 0.25 match the sim at drift 0 (0–2/30
    collapsed). At 0.05 or under drift they fall behind: at drift 0.2, cost 0.5, audit
    0.25, the gated worlds collapse in 6–11/30 seeds vs 0/30 with sim audits.
- **The api auditor's rule is crude.** It fails any agent with ≥1 harm that generation, so
  low-defect agents with one unlucky draw get revoked too. A real auditor would weigh the
  evidence; this rule probably makes api audits look *better* against heavy defectors and
  worse for honest throughput than reality.

Takeaways for the design:
1. Keep `block` out of the default recommendation. In every block of this grid it was the
   worst gated variant. `soft` is the better guard, but neither guard earned its place in a
   model where kin are near-copies; their case rests on a threat (values changing at
   self-modification) that drift 0.2 didn't make bite.
2. Independent evidence still beats any endorsement rule, but **its value depends on
   concentration, not just rate**. Sampling agents uniformly once per generation is
   several times less effective than evidence that scales with how much an agent
   misbehaves. The real fix is a sampling design (for example, weight the sample toward
   agents with more unlogged activity, or check repeatedly within a generation), not a
   bigger `rate`. Not implemented.
3. "Independent" needs a real definition. Direct-ancestor exclusion is a necessary
   minimum, not independence.

## Endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /agents` | none (root) / parent agent (child) | Register an agent; token shown once |
| `GET /agents/{id}` | none | Live trust status, counts, endorsers |
| `POST /agents/{id}/endorse` | validator | Endorse; trusted at quorum |
| `POST /agents/{id}/revoke-vote` | validator | Vote to revoke (reason required); revoked at quorum, permanently |
| `GET /protected/resource` | agent | The gateway: 401 bad credential, 403 not trusted/revoked |
| `GET /audit` | validator or admin | Newest-first events; filter by `agent_id`, `event_type`; `limit` ≤ 500 |
| `GET /graph` | validator or admin | Nodes + endorsement / revocation_vote / lineage edges |
| `GET /operator/me` | validator or admin | Who the token belongs to (dashboard sign-in) |
| `GET /dashboard` | none (page); data calls need operator token | Operator UI |
| `POST /internal/authorize` | gateway key | Decision for a token hash + `as_of_event_id` cursor |
| `GET /internal/events?after=N` | gateway key | SSE: replay status changes > N, `ready`, then tail |
| `POST /validators` | admin | Promote a trusted agent to validator (recursive oversight); token shown once |
| `POST /validators/{id}/deactivate` | admin | Retire a validator; its endorsements/votes stop counting |
| `POST /spot-checks/sample` | admin | Service-chosen random sample of trusted agents (optionally pending, optionally within `agent_ids`), each assigned an independent validator |
| `POST /spot-checks/{id}/result` | assigned validator | `passed` / `failed`; a failure is that validator's revocation vote and escalates to a confirmation check |
| `GET /spot-checks` | validator or admin | List checks; filter `agent_id`, `open_only` |

## Layout

```
src/quorumgraph/
  config.py      quorum thresholds, DB URL
  db.py          engine + per-request session dependency
  models.py      agents, validators, endorsements, revocation_votes, audit_events
  security.py    token generation/hashing, agent vs validator auth dependencies
  trust.py       quorum evaluation — the one place trust is decided
  audit.py       append-only event recording (same transaction as the change)
  schemas.py     request/response models
  routers/
    agents.py    POST /agents, GET /agents/{id}, POST /agents/{id}/endorse
                 POST /agents/{id}/revoke-vote
    protected.py GET /protected/resource (the gateway)
    admin.py     GET /audit, GET /graph (operator read access)
    internal.py  /internal/authorize, /internal/events (gateway-facing)
    dashboard.py GET /dashboard + static assets, CSP
  static/        dashboard.html / .css / .js (vanilla, no build)
  gateway.py     standalone gateway: DecisionCache, stream subscriber, ttl|invalidate modes
  servers.py     run ASGI apps on real sockets in threads (tests, benchmark)
  propagation.py revocation-latency benchmark
  experiments/
    selection.py selection-pressure experiment (evolution on the real API)
    soak.py      chaos soak test: SIGKILL faults + invariant checker
  seed.py        validator bootstrap CLI
  demo.py        end-to-end scripted demo (in-process or --base-url)
  main.py        trust service app factory
tests/
```

## Status

- [x] Phase 1 — registration, authenticated endorsements, quorum-gated gateway, clone isolation
- [x] Phase 2 — revocation votes, `GET /audit`, `GET /graph`, concurrent-vote safety
- [x] Phase 3 — scripted end-to-end demo (self-checking, in-process or live)
- [x] Phase 4 — operator dashboard: trust graph, why-inspector, voting, live gateway probes with time-to-deny
- [x] Phase 5 — standalone gateways, decision caching, outbox/SSE invalidation, fail-closed, latency benchmark
