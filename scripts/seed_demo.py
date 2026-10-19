#!/usr/bin/env python3
"""Seed a demo database for screenshots and demos.

Creates one demo organization, an admin user, assets, domains, findings,
alerts, a Slack alert integration (no credentials), and scan history --
all from the FIXTURE objects below. **No network access** (there is no
network client imported and no external call; the tests in
``backend/tests/test_seed_demo.py`` enforce that), so it is safe to run
anywhere.

Database guard (defence in depth with ``scripts/db_guard.sh``):

- ``scratch_*``  -> delegated to ``scripts/db_guard.sh`` (same rule everywhere);
- ``demo_*``     -> accepted by this script's own check (db_guard.sh only
                    knows ``scratch_*``/``e2e_*``);
- anything else  -> refused, exit 2, nothing touched.

Prereqs: migrations applied (``make migrate``) and backend deps available
(the backend venv). Usage:

    DATABASE_URL=postgresql://sentinel:sentinelpass@localhost:5432/demo_local \
        backend/venv/bin/python scripts/seed_demo.py

Demo login: username ``demo``; the password is generated randomly at seed
time and printed ONCE to the terminal (never stored in docs, logs, or this
repository). If the printout is lost, drop the demo DB and reseed.

Idempotency: refuses to run twice against the same DB (the demo org name
already existing aborts with a clear message; drop the scratch/demo DB
instead of un-seeding).
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_PREFIXES = ("demo_", "scratch_")
DEV_DB_NAME = "sentinelasm"

# FIXTURE data ----------------------------------------------------------------
# Entirely synthetic. Domain names use RFC 2606 ".example" to stay unroutable;
# nothing here is fetched, scanned, or contacted by the seeder.
FIXTURE = {
    "organization": "Demo Corp",
    "user": {
        "username": "demo",
        "email": "demo@example.com",
        "role": "admin",
        # The password is NOT a fixture: generate_demo_password() supplies a
        # random one-time value at seed time (printed once to the terminal).
    },
    "assets": [
        {
            "name": "Marketing Site",
            "criticality": "prod",
            "exposure": "internet",
            "domain": {
                "domain": "www.demo-corp.example",
                "registrar": "Fixture Registrar LLC",
                "asn": "AS64512",
                "hosting_provider": "Fixture Cloud",
            },
            "findings": [
                ("Outdated TLS configuration", "high",
                 "TLS 1.0/1.1 still offered on the front-door listener."),
                ("Missing security headers", "medium",
                 "Content-Security-Policy and X-Content-Type-Options absent."),
                ("Directory listing exposed", "low",
                 "/assets/ returns an autoindex."),
            ],
        },
        {
            "name": "Internal Wiki",
            "criticality": "dev",
            "exposure": "internet",
            "domain": {
                "domain": "wiki.demo-corp.example",
                "registrar": "Fixture Registrar LLC",
                "asn": "AS64513",
                "hosting_provider": "Fixture Cloud",
            },
            "findings": [
                ("Admin panel reachable without SSO", "critical",
                 "/admin answers 200 from the internet without SSO."),
                ("Expired SSL certificate", "high",
                 "Certificate chain expired 30+ days ago."),
            ],
        },
    ],
    "alerts": [
        ("Critical finding raised: Admin panel reachable without SSO",
         "critical", False),
        ("High finding raised: Expired SSL certificate", "high", False),
        ("Weekly digest sent", "info", True),
    ],
    "alert_integration": {
        # Credentials deliberately left empty: encrypted-at-rest columns stay
        # NULL so the seeder never needs SECRETS_ENCRYPTION_KEY.
        "name": "Demo Slack",
        "channel": "slack",
        "min_severity": "high",
    },
    "scan_history": [
        ("www.demo-corp.example", "completed", "full"),
        ("wiki.demo-corp.example", "completed", "full"),
    ],
}
# -----------------------------------------------------------------/FIXTURE data


def refuse(message: str, code: int = 2) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(code)


def db_name(database_url: str) -> str:
    """Extract the database name (same parsing as db_guard.sh, no creds)."""
    path = database_url.split("?", 1)[0]
    return path.rsplit("/", 1)[-1]


def enforce_db_guard(database_url: str) -> str:
    """demo_/scratch_ only; scratch_* additionally goes through db_guard.sh."""
    name = db_name(database_url)
    if not name:
        refuse("db_guard: DATABASE_URL does not name a database")
    if name == DEV_DB_NAME:
        refuse(
            f"db_guard: REFUSING -- {name!r} is the development database; "
            "use a demo_/scratch_ database (see scripts/db_guard.sh)"
        )
    if not name.startswith(ALLOWED_PREFIXES):
        refuse(
            f"db_guard: REFUSING -- {name!r} is not a demo_/scratch_ database "
            "(scripts/db_guard.sh rule; e.g. demo_local or scratch_seed)"
        )
    if name.startswith("scratch_"):
        guard = ROOT / "scripts" / "db_guard.sh"
        result = subprocess.run(
            ["bash", str(guard)],
            env={**os.environ, "DATABASE_URL": database_url},
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            tpl = (result.stdout + result.stderr).strip() or "db_guard failed"
            refuse(f"db_guard: REFUSED by scripts/db_guard.sh -- {tpl}")
    if name.startswith("demo_"):
        print(f"db_guard: target database is '{name}' (demo_ -- seeder check)")
    return name


def generate_demo_password() -> str:
    """Random one-time demo password (~21 chars of [A-Za-z0-9_-]).

    Clears the 8-char policy with a wide margin; returned to the caller for
    a single terminal print, never persisted anywhere else.
    """
    return secrets.token_urlsafe(15)


def create_schema_and_seed(database_url: str, name: str,
                           password: str) -> None:
    sys.path.insert(0, str(ROOT / "backend"))

    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session

    from models.alert import Alert
    from models.alert_integration import AlertChannel, AlertIntegration, AlertSeverity
    from models.asset import Asset
    from models.base import Base
    from models.domain import Domain
    from models.finding import Finding
    from models.organization import Organization
    from models.scan_history import ScanHistory
    from models.user import User
    from auth.security import hash_password

    engine = create_engine(database_url)
    inspector = __import__("sqlalchemy").inspect(engine)
    if not inspector.has_table("organizations"):
        refuse(
            "seed_demo: tables are missing -- apply migrations first "
            "(DATABASE_URL=<demo db> make migrate), then rerun"
        )

    fixture_user = FIXTURE["user"]
    with Session(engine) as session:
        existing = session.scalar(
            select(Organization).where(Organization.name == FIXTURE["organization"])
        )
        if existing is not None:
            refuse(
                f"seed_demo: organization {FIXTURE['organization']!r} already "
                "exists in this database -- nothing to do (idempotent; drop "
                "the DB to reseed)"
            )

        org = Organization(name=FIXTURE["organization"])
        session.add(org)
        session.flush()

        user = User(
            organization_id=org.id,
            username=fixture_user["username"],
            email=fixture_user["email"],
            password_hash=hash_password(password),
            role=fixture_user["role"],
        )
        session.add(user)
        session.flush()

        assets: list[Asset] = []
        for spec in FIXTURE["assets"]:
            asset = Asset(
                organization_id=org.id,
                name=spec["name"],
                criticality=spec["criticality"],
                exposure=spec["exposure"],
            )
            session.add(asset)
            session.flush()
            session.add(Domain(organization_id=org.id, asset_id=asset.id,
                               **spec["domain"]))
            for title, severity, description in spec["findings"]:
                session.add(Finding(
                    organization_id=org.id,
                    asset_id=asset.id,
                    title=title,
                    severity=severity,
                    category="fixture",
                    description=description,
                ))
            assets.append(asset)
        session.flush()

        for (title, severity, read) in FIXTURE["alerts"]:
            session.add(Alert(
                organization_id=org.id,
                asset_id=assets[0].id,
                title=title,
                severity=severity,
                message=f"[fixture] {title}",
                read=read,
            ))

        integ = FIXTURE["alert_integration"]
        session.add(AlertIntegration(
            organization_id=org.id,
            created_by=user.id,
            name=integ["name"],
            channel=AlertChannel(integ["channel"]),
            min_severity=AlertSeverity(integ["min_severity"]),
        ))

        for target, status, scope in FIXTURE["scan_history"]:
            session.add(ScanHistory(
                organization_id=org.id,
                asset_id=assets[0].id if "www." in target else assets[1].id,
                target=target,
                status=status,
                scope=scope,
            ))

        session.commit()

    print(
        f"seed_demo: done -> {name}: org copied from FIXTURE, 1 user, "
        f"{len(FIXTURE['assets'])} assets, "
        f"{sum(len(a['findings']) for a in FIXTURE['assets'])} findings, "
        f"{len(FIXTURE['alerts'])} alerts, 1 alert integration (no "
        "credentials), 2 scan-history rows."
    )


def main() -> None:
    database_url = os.environ.get("DATABASE_URL", "")
    if not database_url:
        refuse("seed_demo: DATABASE_URL is not set -- refusing to run")
    name = enforce_db_guard(database_url)
    password = generate_demo_password()
    create_schema_and_seed(database_url, name, password)
    # One-time credential printout: the ONLY copy the operator gets (it is
    # not written to the DB, docs, or any log line). Shown after the commit
    # so a failed run never dangles a password for a half-seeded org.
    print(
        "─────────────────────────────────────────────────────────\n"
        f"  Demo user:   demo\n"
        f"  Password (shown ONCE; record it now): {password}\n"
        "─────────────────────────────────────────────────────────"
    )


if __name__ == "__main__":
    main()
