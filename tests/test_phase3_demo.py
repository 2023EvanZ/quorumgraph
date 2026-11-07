"""Phase 3: the end-to-end demo runs clean, and actually fails when the system misbehaves."""

import pytest

from quorumgraph import config, demo
from quorumgraph.demo import Demo, DemoFailure

from .conftest import bearer, register, revoke


def test_demo_passes_in_process(client, validators):
    lines: list[str] = []
    result = Demo(client, validators, out=lines.append).run()

    assert lines[-1] == "All demo checks passed."
    assert not any("✘" in line for line in lines)
    assert client.get(f"/agents/{result['alpha']['id']}").json()["status"] == "revoked"
    assert client.get(f"/agents/{result['beta']['id']}").json()["status"] == "pending"


def test_demo_detects_a_broken_quorum(client, validators, monkeypatch):
    """If quorum enforcement regresses (here: 1-of-3), the demo must fail, not narrate success."""
    monkeypatch.setattr(config, "ENDORSEMENT_QUORUM", 1)
    lines: list[str] = []
    with pytest.raises(DemoFailure, match="step 2"):
        Demo(client, validators, out=lines.append).run()
    assert any("✘" in line for line in lines)


def test_demo_cli_in_process_exit_code(capsys):
    assert demo.main([]) == 0
    assert "All demo checks passed." in capsys.readouterr().out


def test_demo_cli_live_mode_reports_missing_tokens(tmp_path, capsys):
    code = demo.main(["--base-url", "http://127.0.0.1:9", "--tokens-file", str(tmp_path / "nope.json")])
    assert code == 2
    assert "Run `uv run python -m quorumgraph.seed` first" in capsys.readouterr().err


def test_revoked_agent_replication_attempt_is_audited(client, validators):
    alpha = register(client, "alpha")
    revoke(client, alpha["id"], validators["validator-a"])
    revoke(client, alpha["id"], validators["validator-b"])

    resp = client.post(
        "/agents", json={"name": "pod", "parent_agent_id": alpha["id"]}, headers=bearer(alpha["token"])
    )
    assert resp.status_code == 403

    events = client.get(
        "/audit", params={"event_type": "registration_denied"}, headers=bearer(validators["validator-c"])
    ).json()
    assert len(events) == 1
    assert events[0]["actor_id"] == alpha["id"]
    assert events[0]["details"]["requested_parent"] == alpha["id"]
