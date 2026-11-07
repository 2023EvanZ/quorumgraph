"""Soak harness: offline invariant checks catch corrupted state; duration parsing."""

import argparse
import sqlite3

import pytest
from sqlalchemy.orm import sessionmaker

from quorumgraph.db import Base, make_engine
from quorumgraph.experiments.soak import Ledger, offline_checks, parse_duration


def _db(tmp_path):
    path = tmp_path / "s.db"
    engine = make_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    engine.dispose()
    con = sqlite3.connect(path)
    con.executescript("""
        INSERT INTO validators (id, name, credential_hash, active) VALUES
          ('va','A','h1',1), ('vb','B','h2',1), ('vc','C','h3',1);
        -- good: pending -> trusted with 2 endorsements
        INSERT INTO agents (id, name, token_hash, status, created_at) VALUES ('good','g','t1','TRUSTED','2026-01-01');
        INSERT INTO endorsements (validator_id, agent_id, created_at) VALUES ('va','good','2026-01-01'), ('vb','good','2026-01-01');
        INSERT INTO audit_events (event_type, agent_id, details, created_at) VALUES
          ('agent_status_changed','good','{"old":"pending","new":"trusted"}','2026-01-01');
    """)
    con.commit()
    return path, con


def test_offline_checks_pass_on_consistent_state(tmp_path):
    path, con = _db(tmp_path)
    con.close()
    ledger = Ledger()
    result = offline_checks(path, ledger)
    assert ledger.violations == []
    assert result["trusted_in_db"] == 1


def test_offline_checks_catch_duplicate_transition_bad_status_and_lost_revocation(tmp_path):
    path, con = _db(tmp_path)
    con.executescript("""
        -- duplicate transition (the race class fixed in Phase 2)
        INSERT INTO audit_events (event_type, agent_id, details, created_at) VALUES
          ('agent_status_changed','good','{"old":"pending","new":"trusted"}','2026-01-01');
        -- revoked with only one vote, and no transition recorded
        INSERT INTO agents (id, name, token_hash, status, created_at) VALUES ('bad','b','t2','REVOKED','2026-01-01');
        INSERT INTO revocation_votes (validator_id, agent_id, reason, created_at) VALUES ('va','bad','x','2026-01-01');
        INSERT INTO agents (id, name, token_hash, status, created_at) VALUES ('lost','l','t3','PENDING','2026-01-01');
    """)
    con.commit()
    con.close()
    ledger = Ledger()
    ledger.revoked_acked.add("lost")  # client was told it's revoked, DB says pending
    offline_checks(path, ledger)
    kinds = sorted(v["invariant"] for v in ledger.violations)
    assert "O1" in kinds   # good: duplicate transition
    assert "O2" in kinds   # bad: stored revoked, no transition
    assert "O3" in kinds   # bad: revoked with 1 vote
    assert "O4" in kinds   # lost: acknowledged revocation not persisted


def test_ledger_memory_is_bounded():
    from quorumgraph.experiments.soak import Tracked

    ledger = Ledger(keep=10)
    for i in range(100):
        ledger.add(Tracked(id=str(i), token="t"))
    assert len(ledger.agents) <= 20
    assert "99" in ledger.agents and "0" not in ledger.agents


@pytest.mark.parametrize("text,seconds", [("90s", 90), ("15m", 900), ("8h", 28800), ("2.5h", 9000), ("30", 30)])
def test_parse_duration(text, seconds):
    assert parse_duration(text) == seconds


def test_parse_duration_rejects_garbage():
    with pytest.raises(argparse.ArgumentTypeError):
        parse_duration("eight hours")
