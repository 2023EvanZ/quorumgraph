"""Phase 4: dashboard serving, operator identity, and gateway CORS.

The dashboard's JS behaviour is verified in a real browser (see README);
these tests pin the server-side contract it depends on.
"""

import re

import pytest
from fastapi.testclient import TestClient

from quorumgraph.gateway import create_gateway_app

from .conftest import bearer, register

ORIGIN = "http://127.0.0.1:8000"


def test_dashboard_page_served_with_strict_csp(client):
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "<title>QuorumGraph</title>" in r.text
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp
    assert "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("asset,ctype", [("dashboard.js", "javascript"), ("dashboard.css", "text/css")])
def test_dashboard_assets_served(client, asset, ctype):
    r = client.get(f"/dashboard/static/{asset}")
    assert r.status_code == 200
    assert ctype in r.headers["content-type"]


def test_dashboard_js_never_uses_innerhtml(client):
    """Agent names are attacker-controlled input; the page must only use textContent."""
    js = client.get("/dashboard/static/dashboard.js").text
    assert not re.search(r"\.(innerHTML|outerHTML)\b|insertAdjacentHTML\s*\(|document\.write\s*\(", js)


def test_dashboard_not_in_openapi(client):
    paths = client.get("/openapi.json").json()["paths"]
    assert "/dashboard" not in paths


def test_operator_me(client, validators, monkeypatch):
    r = client.get("/operator/me", headers=bearer(validators["validator-b"]))
    assert r.json() == {"operator_id": "validator-b", "kind": "validator",
                        "lineage_guard": "soft", "kin_radius": 0, "spot_check_escalation": True}

    from quorumgraph import config
    monkeypatch.setattr(config, "ADMIN_TOKEN", "adm")
    me = client.get("/operator/me", headers=bearer("adm")).json()
    assert (me["operator_id"], me["kind"]) == ("admin", "admin")

    agent = register(client, "alpha")
    assert client.get("/operator/me", headers=bearer(agent["token"])).status_code == 401
    assert client.get("/operator/me").status_code == 401


def _gw(cors=()):
    return create_gateway_app(trust_url="http://127.0.0.1:1", gateway_secret="s", mode="ttl", ttl=1, cors_origins=cors)


def test_gateway_cors_disabled_by_default():
    with TestClient(_gw()) as c:
        r = c.get("/gateway/stats", headers={"Origin": ORIGIN})
        assert r.status_code == 200
        assert "access-control-allow-origin" not in r.headers


def test_gateway_cors_allows_configured_origin_only():
    with TestClient(_gw(cors=(ORIGIN,))) as c:
        ok = c.get("/gateway/stats", headers={"Origin": ORIGIN})
        assert ok.headers["access-control-allow-origin"] == ORIGIN
        # The dashboard reads X-QG-Cache cross-origin, so it must be exposed.
        assert "x-qg-cache" in ok.headers["access-control-expose-headers"].lower()
        assert "access-control-allow-credentials" not in ok.headers

        pre = c.options("/protected/resource", headers={
            "Origin": ORIGIN, "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization"})
        assert pre.status_code == 200

        evil = c.get("/gateway/stats", headers={"Origin": "http://evil.example"})
        assert "access-control-allow-origin" not in evil.headers
        bad_method = c.options("/protected/resource", headers={
            "Origin": ORIGIN, "Access-Control-Request-Method": "POST"})
        assert bad_method.status_code == 400


def test_gateway_cors_origins_from_env(monkeypatch):
    from quorumgraph.gateway import create_gateway_app_from_env

    monkeypatch.setenv("QG_GATEWAY_SECRET", "s")
    monkeypatch.setenv("QG_GATEWAY_MODE", "ttl")
    monkeypatch.setenv("QG_GATEWAY_CORS_ORIGINS", f" {ORIGIN} , http://localhost:8000 ,")
    with TestClient(create_gateway_app_from_env()) as c:
        for origin in (ORIGIN, "http://localhost:8000"):
            r = c.get("/gateway/stats", headers={"Origin": origin})
            assert r.headers["access-control-allow-origin"] == origin
