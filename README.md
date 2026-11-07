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
`.validator_tokens.json`) or `QG_ADMIN_TOKEN` (read-only).

- **Trust graph**: validators on the left, agents laid out by lineage. Edges: endorsement
  (green), revocation vote (red, reason on hover), dashed = from an inactive validator so it
  doesn't count, grey arrow = spawned. Click an agent to highlight its edges.
- **Inspector**: a plain-English "why is this agent trusted / pending / revoked", quorum meters,
  each vote with its reason, parent/children, the agent's audit timeline, and Endorse /
  Vote-to-revoke buttons (acting as the signed-in validator).
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
