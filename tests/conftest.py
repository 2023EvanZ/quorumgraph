import pytest
from fastapi.testclient import TestClient

from quorumgraph.main import create_app
from quorumgraph.seed import seed_validators


@pytest.fixture
def app():
    return create_app("sqlite://")  # fresh in-memory DB per test


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture
def db(app):
    with app.state.sessionmaker() as session:
        yield session


@pytest.fixture
def validators(app) -> dict[str, str]:
    """{'validator-a': token, 'validator-b': token, 'validator-c': token}"""
    with app.state.sessionmaker() as session:
        tokens = seed_validators(session)
        session.commit()
    return tokens


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def register(client, name: str, parent_id: str | None = None, token: str | None = None) -> dict:
    body = {"name": name}
    if parent_id:
        body["parent_agent_id"] = parent_id
    resp = client.post("/agents", json=body, headers=bearer(token) if token else {})
    assert resp.status_code == 201, resp.text
    return resp.json()


def endorse(client, agent_id: str, validator_token: str):
    return client.post(f"/agents/{agent_id}/endorse", headers=bearer(validator_token))


def revoke(client, agent_id: str, validator_token: str, reason: str = "compromised"):
    return client.post(f"/agents/{agent_id}/revoke-vote", json={"reason": reason}, headers=bearer(validator_token))


def access(client, agent_token: str):
    return client.get("/protected/resource", headers=bearer(agent_token))
