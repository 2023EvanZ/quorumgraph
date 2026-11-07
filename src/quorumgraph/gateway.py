"""Standalone authorization gateway with a decision cache.

Two modes, to make the consistency tradeoff visible:

  ttl         Cache decisions for TTL seconds. Nothing else. After a revocation
              the gateway keeps serving the cached ALLOW until the entry
              expires: revocation latency ≈ up to TTL. If the trust service
              goes down, cached decisions keep being served (availability
              over correctness).

  invalidate  Same cache (TTL kept as a backstop), plus a subscription to the
              trust service's status-change stream. A change for agent X
              evicts X's entries immediately. Safety rules:
                • The cache is only used while the stream is connected AND
                  has caught up (`ready`). Disconnected ⇒ every request goes
                  to the trust service ⇒ if that's down too, 503 (fail closed).
                • On reconnect the stream resumes from our cursor, replaying
                  anything we missed (unlike fire-and-forget pub/sub).
                • A decision fetched *before* an invalidation we've already
                  applied is never cached (see DecisionCache.put).

Run standalone (one process per gateway):
    QG_TRUST_URL=http://127.0.0.1:8000 QG_GATEWAY_SECRET=dev QG_GATEWAY_MODE=invalidate \\
    QG_GATEWAY_NAME=B uv run uvicorn quorumgraph.gateway:create_gateway_app_from_env --factory --port 8002
"""

import asyncio
import contextlib
import json
import os
import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

import httpx
from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .security import hash_token

Mode = Literal["ttl", "invalidate"]


@dataclass(frozen=True)
class Decision:
    agent_id: str
    allowed: bool
    status: str
    reason: str
    as_of_event_id: int


class TrustServiceUnavailable(Exception):
    pass


class DecisionCache:
    """token_hash -> Decision with TTL, plus per-agent invalidation floors.

    Thread-safe: request handlers run in a threadpool, the subscriber on the
    event loop.
    """

    def __init__(self, ttl: float, clock: Callable[[], float] = time.monotonic):
        self.ttl = ttl
        self.clock = clock
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[Decision, float]] = {}  # token_hash -> (decision, expires_at)
        self._by_agent: dict[str, set[str]] = {}
        # agent_id -> highest status-change event id applied. A decision whose
        # as_of_event_id is below this predates a change we know about.
        self._floor: dict[str, int] = {}

    def get(self, token_hash: str) -> Decision | None:
        with self._lock:
            hit = self._entries.get(token_hash)
            if hit is None:
                return None
            decision, expires_at = hit
            if self.clock() >= expires_at:
                self._evict(token_hash)
                return None
            return decision

    def put(self, token_hash: str, decision: Decision) -> bool:
        """Cache a decision unless it is provably stale. Returns False if refused.

        The race this closes: request R asks the trust service (gets ALLOW,
        as_of=10); revocation commits as event 11; the stream delivers event 11
        and we invalidate (nothing cached yet); THEN R's response arrives and
        would be cached, an ALLOW that outlives the revocation by a full TTL.
        Since 10 < floor(11), we refuse it.
        """
        with self._lock:
            if decision.as_of_event_id < self._floor.get(decision.agent_id, 0):
                return False
            self._entries[token_hash] = (decision, self.clock() + self.ttl)
            self._by_agent.setdefault(decision.agent_id, set()).add(token_hash)
            return True

    def invalidate_agent(self, agent_id: str, event_id: int) -> int:
        """Evict this agent's entries that predate ``event_id``. Returns how many were evicted.

        Entries with as_of_event_id >= event_id were computed after that event
        committed, so they already reflect it and are kept. (Without this, the
        event for a change we just fetched would evict the fresh entry, costing
        an extra trust-service round trip per gateway per status change.)
        """
        with self._lock:
            self._floor[agent_id] = max(self._floor.get(agent_id, 0), event_id)
            evicted = 0
            for h in list(self._by_agent.get(agent_id, ())):
                if self._entries[h][0].as_of_event_id < event_id:
                    self._evict(h)
                    evicted += 1
            return evicted

    def _evict(self, token_hash: str) -> None:
        decision, _ = self._entries.pop(token_hash)
        if (s := self._by_agent.get(decision.agent_id)) is not None:
            s.discard(token_hash)

    def __len__(self) -> int:
        return len(self._entries)


class Gateway:
    def __init__(
        self,
        *,
        name: str,
        trust_url: str,
        gateway_secret: str,
        mode: Mode,
        ttl: float,
        http: httpx.Client | None = None,
    ):
        self.name = name
        self.trust_url = trust_url
        self.gateway_secret = gateway_secret
        self.mode = mode
        self.cache = DecisionCache(ttl)
        self.stats: Counter[str] = Counter()
        self.stream_ready = False
        self.cursor: int | None = None
        self.http = http or httpx.Client(base_url=trust_url, timeout=2.0)

    # --- decisions -------------------------------------------------------------

    def cache_usable(self) -> bool:
        return self.mode == "ttl" or self.stream_ready

    def fetch(self, token_hash: str) -> Decision | None:
        """Ask the trust service. None = unknown credential."""
        try:
            r = self.http.post(
                "/internal/authorize", json={"token_hash": token_hash}, headers={"X-Gateway-Key": self.gateway_secret}
            )
        except httpx.HTTPError as e:
            raise TrustServiceUnavailable(str(e)) from e
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            raise TrustServiceUnavailable(f"trust service returned {r.status_code}")
        return Decision(**r.json())

    def authorize(self, token_hash: str) -> tuple[Decision | None, str]:
        """Returns (decision, cache_result) where cache_result is hit / miss / bypass."""
        if self.cache_usable() and (d := self.cache.get(token_hash)) is not None:
            self.stats["cache_hits"] += 1
            return d, "hit"

        if not self.cache_usable():
            self.stats["cache_bypassed"] += 1
            return self.fetch(token_hash), "bypass"

        self.stats["cache_misses"] += 1
        for _ in range(3):
            d = self.fetch(token_hash)
            # Unknown tokens aren't cached: random garbage tokens shouldn't be able to fill memory.
            if d is None or not self.cache_usable() or self.cache.put(token_hash, d):
                return d, "miss"
            self.stats["stale_put_refused"] += 1  # raced an invalidation: ask again
        return d, "miss"  # still racing after 3 tries: serve the newest answer, uncached

    # --- invalidation stream -----------------------------------------------------

    def _on_event(self, event: str, event_id: str | None, data: str) -> None:
        if event == "ready":
            self.cursor = int(event_id)
            self.stream_ready = True
        elif event == "status_changed":
            payload = json.loads(data)
            evicted = self.cache.invalidate_agent(payload["agent_id"], int(event_id))
            self.cursor = int(event_id)
            self.stats["invalidations"] += 1
            self.stats["entries_evicted"] += evicted

    async def run_subscriber(self) -> None:
        backoff = 0.1
        while True:
            try:
                params = {"after": self.cursor} if self.cursor is not None else {}
                timeout = httpx.Timeout(5.0, read=3.0)  # > keepalive interval: detects a dead peer in ≤3s
                async with httpx.AsyncClient(base_url=self.trust_url, timeout=timeout) as client:
                    async with client.stream(
                        "GET", "/internal/events", params=params, headers={"X-Gateway-Key": self.gateway_secret}
                    ) as r:
                        r.raise_for_status()
                        backoff = 0.1
                        self.stats["stream_connects"] += 1
                        event, eid, data = "message", None, ""
                        async for line in r.aiter_lines():
                            if line == "":
                                if eid is not None or data:
                                    self._on_event(event, eid, data)
                                event, eid, data = "message", None, ""
                            elif line.startswith(":"):
                                continue  # keepalive comment
                            else:
                                field, _, value = line.partition(":")
                                value = value.removeprefix(" ")
                                if field == "event":
                                    event = value
                                elif field == "id":
                                    eid = value
                                elif field == "data":
                                    data = value
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — any failure means "not caught up"; reconnect
                self.stats["stream_errors"] += 1
            # Stream ended or failed: stop trusting the cache until we're caught up again.
            self.stream_ready = False
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 2.0)

    def snapshot(self) -> dict:
        return {
            "name": self.name,
            "mode": self.mode,
            "ttl_seconds": self.cache.ttl,
            "cache_size": len(self.cache),
            "cache_usable": self.cache_usable(),
            "stream_ready": self.stream_ready if self.mode == "invalidate" else None,
            "cursor": self.cursor,
            **self.stats,
        }


_DOCUMENT = "CONFIDENTIAL: Q3 launch codes are 'hunter2'. (Simulated secret.)"
_bearer = HTTPBearer(auto_error=False)


def create_gateway_app(
    *,
    trust_url: str,
    gateway_secret: str,
    name: str = "gateway",
    mode: Mode = "invalidate",
    ttl: float = 5.0,
    cors_origins: tuple[str, ...] = (),
) -> FastAPI:
    """``cors_origins``: browser origins allowed to call this gateway (e.g. the
    trust service's /dashboard). Empty = no CORS headers, so browsers on other
    origins can't read responses. Only GET is allowed; credentials are sent as
    an explicit Authorization header, never cookies."""
    gw = Gateway(name=name, trust_url=trust_url, gateway_secret=gateway_secret, mode=mode, ttl=ttl)

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        task = asyncio.create_task(gw.run_subscriber()) if mode == "invalidate" else None
        yield
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        gw.http.close()

    app = FastAPI(title=f"QuorumGraph Gateway {name}", lifespan=lifespan)
    app.state.gateway = gw
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(cors_origins),
            allow_methods=["GET"],
            allow_headers=["Authorization"],
            expose_headers=["X-QG-Gateway", "X-QG-Cache"],
            allow_credentials=False,
        )

    @app.get("/protected/resource", tags=["gateway"])
    def protected_resource(
        response: Response, creds: HTTPAuthorizationCredentials | None = Depends(_bearer)
    ) -> dict:
        if creds is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing agent credential",
                                headers={"WWW-Authenticate": "Bearer"})
        try:
            decision, cache_result = gw.authorize(hash_token(creds.credentials))
        except TrustServiceUnavailable:
            # Fail closed: if we can't verify, we don't allow.
            gw.stats["unavailable"] += 1
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "authorization unavailable (fail-closed)")

        headers = {"X-QG-Gateway": name, "X-QG-Cache": cache_result}
        if decision is None:
            gw.stats["unknown"] += 1
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid agent credential",
                                headers={"WWW-Authenticate": "Bearer", **headers})
        if not decision.allowed:
            gw.stats["denied"] += 1
            raise HTTPException(status.HTTP_403_FORBIDDEN, decision.reason, headers=headers)

        gw.stats["allowed"] += 1
        response.headers.update(headers)
        return {"agent_id": decision.agent_id, "gateway": name, "document": _DOCUMENT}

    @app.get("/gateway/stats", tags=["gateway"])
    def stats() -> dict:
        return gw.snapshot()

    return app


def create_gateway_app_from_env() -> FastAPI:
    secret = os.getenv("QG_GATEWAY_SECRET")
    if not secret:
        raise RuntimeError("QG_GATEWAY_SECRET must be set (and match the trust service's)")
    mode = os.getenv("QG_GATEWAY_MODE", "invalidate")
    if mode not in ("ttl", "invalidate"):
        raise RuntimeError("QG_GATEWAY_MODE must be 'ttl' or 'invalidate'")
    return create_gateway_app(
        trust_url=os.getenv("QG_TRUST_URL", "http://127.0.0.1:8000"),
        gateway_secret=secret,
        name=os.getenv("QG_GATEWAY_NAME", "gateway"),
        mode=mode,  # type: ignore[arg-type]
        ttl=float(os.getenv("QG_GATEWAY_TTL", "5")),
        cors_origins=tuple(o.strip() for o in os.getenv("QG_GATEWAY_CORS_ORIGINS", "").split(",") if o.strip()),
    )
