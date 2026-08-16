"""Create the first operator. `python -m dotmac_integrator.bootstrap_operator`.

Guarding `/operations/**` creates a chicken-and-egg problem: the surface that
could create an operator is itself operator-guarded, and it should be — there is
no HTTP self-registration path for a platform actor, ever. So the first one is
made out of band, by whoever already has the deploy credentials.

## Why the OWNER DSN

`MIGRATION_DATABASE_URL`, the same role that runs migrations, deliberately not
the online `DATABASE_URL`. Creating an operator is the same trust boundary as
changing the schema: if you can do one you can do the other, and requiring the
owner credential means the online role — the one a compromised web process
holds — cannot mint itself an operator.

## Why the password never appears in argv

`--password` would put the credential in the process table, the shell history
and every `ps` a colleague runs. It is read from `OPERATOR_PASSWORD` (for an
automated bootstrap) or prompted without echo, and it is never logged, echoed
or included in the summary this prints.

Re-running for an existing email updates the password and reactivates the
account rather than failing, because the second reason anyone runs this is a
lockout.
"""

from __future__ import annotations

import argparse
import os
import sys
from getpass import getpass

from dotmac_kernel.models_platform import PlatformAdmin
from dotmac_kernel.security import hash_password
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

MINIMUM_PASSWORD_LENGTH = 16


def _password() -> str:
    """From the environment, or prompted. Never from argv."""
    supplied = os.getenv("OPERATOR_PASSWORD")
    if supplied is None:
        supplied = getpass("operator password: ")
        if supplied != getpass("repeat: "):
            raise SystemExit("passwords do not match")
    if len(supplied) < MINIMUM_PASSWORD_LENGTH:
        # Length, not composition rules. This credential opens a control plane
        # that can enable connectors against live provider accounts, and it is
        # typed by a machine far more often than by a person.
        raise SystemExit(
            f"password must be at least {MINIMUM_PASSWORD_LENGTH} characters"
        )
    return supplied


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dotmac_integrator.bootstrap_operator")
    parser.add_argument("--email", required=True)
    parser.add_argument(
        "--database-url",
        default=None,
        help="defaults to MIGRATION_DATABASE_URL — the OWNER role, on purpose",
    )
    args = parser.parse_args(argv)

    url = args.database_url or os.getenv("MIGRATION_DATABASE_URL")
    if not url:
        raise SystemExit(
            "MIGRATION_DATABASE_URL is unset. Creating an operator is the same "
            "trust boundary as running a migration; there is deliberately no "
            "fallback to DATABASE_URL, which is the online platform role."
        )

    email = args.email.strip().lower()
    secret = _password()

    engine = create_engine(url, future=True)
    try:
        with Session(engine) as db:
            existing = db.scalars(
                select(PlatformAdmin).where(func.lower(PlatformAdmin.email) == email)
            ).first()
            if existing is None:
                db.add(
                    PlatformAdmin(
                        email=email,
                        password_hash=hash_password(secret),
                        is_active=True,
                    )
                )
                action = "created"
            else:
                existing.password_hash = hash_password(secret)
                existing.is_active = True
                action = "updated"
            db.commit()
    finally:
        engine.dispose()

    # The email, the verb, and nothing else.
    print(f"operator {action}: {email}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
