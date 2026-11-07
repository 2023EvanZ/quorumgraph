"""Create the fixed validator set and print their credentials once.

    uv run python -m quorumgraph.seed

Tokens are written to .validator_tokens.json (gitignored, mode 0600) so the
demo script and Swagger UI can use them. Dev convenience only: in a real
deployment each validator would generate and hold its own credential.
"""

import json
import os
import sys
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from . import config
from .db import Base, make_engine
from .models import Validator
from .security import VALIDATOR_TOKEN_PREFIX, generate_token, hash_token

DEFAULT_VALIDATORS = (("validator-a", "Validator A"), ("validator-b", "Validator B"), ("validator-c", "Validator C"))
TOKENS_FILE = Path(".validator_tokens.json")


def seed_validators(session: Session, validators=DEFAULT_VALIDATORS) -> dict[str, str]:
    """Insert validators and return {validator_id: plaintext_token}. Caller commits."""
    tokens: dict[str, str] = {}
    for vid, name in validators:
        token = generate_token(VALIDATOR_TOKEN_PREFIX)
        session.add(Validator(id=vid, name=name, credential_hash=hash_token(token), active=True))
        tokens[vid] = token
    return tokens


def main() -> int:
    engine = make_engine(config.DATABASE_URL)
    Base.metadata.create_all(engine)
    with sessionmaker(engine)() as session:
        if session.scalar(select(func.count()).select_from(Validator)):
            print("Validators already exist; tokens can't be recovered (only hashes are stored).", file=sys.stderr)
            print("Delete the database file to reset.", file=sys.stderr)
            return 1
        tokens = seed_validators(session)
        session.commit()

    fd = os.open(TOKENS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(tokens, f, indent=2)
    for vid, token in tokens.items():
        print(f"{vid}: {token}")
    print(f"\nSaved to {TOKENS_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
