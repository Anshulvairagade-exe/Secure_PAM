"""
Retire the fictional sample targets from an existing development database.

Older DEV_MODE boots seeded five sample assets and three sample applications
whose *.internal hostnames do not exist. New boots no longer seed them
(SEED_SAMPLE_TARGETS=false). This script soft-deletes exactly those rows,
matched by both name and hostname, so anything a user registered is never
touched. Access requests, sessions, recordings and audit records that
reference them are kept: soft-delete only hides the target.

Dry run by default:
    cd backend && .venv/bin/python -m scripts.retire_sample_targets
Apply:
    cd backend && .venv/bin/python -m scripts.retire_sample_targets --apply
"""

import asyncio
import sys

from sqlalchemy import and_, or_, select

from app.database.session import async_session_factory
from app.models.application import Application
from app.models.asset import Asset

SAMPLE_ASSETS = [
    ("WIN-PROD-01", "win-prod-01.internal"),
    ("WIN-DEV-01", "win-dev-01.internal"),
    ("LINUX-PROD-01", "linux-prod-01.internal"),
    ("LINUX-DEV-01", "linux-dev-01.internal"),
    ("LINUX-STAGING-01", "linux-staging-01.internal"),
]
SAMPLE_APPLICATIONS = [
    ("Admin Portal", "admin.internal"),
    ("Monitoring Dashboard", "monitoring.internal"),
    ("CI/CD Pipeline", "jenkins.internal"),
]


def _matching(model, pairs):
    return select(model).where(
        model.is_deleted == False,  # noqa: E712
        or_(*(and_(model.name == name, model.hostname == host) for name, host in pairs)),
    )


async def main(apply: bool) -> None:
    async with async_session_factory() as db:
        assets = (await db.execute(_matching(Asset, SAMPLE_ASSETS))).scalars().all()
        apps = (await db.execute(_matching(Application, SAMPLE_APPLICATIONS))).scalars().all()
        for row in [*assets, *apps]:
            print(f"{'retire' if apply else 'would retire'}: {type(row).__name__} {row.name} ({row.hostname})")
            if apply:
                row.is_deleted = True
                row.enabled = False
        if apply:
            await db.commit()
        print(f"{len(assets)} sample assets and {len(apps)} sample applications "
              f"{'retired (soft-deleted)' if apply else 'matched; rerun with --apply to retire them'}.")


if __name__ == "__main__":
    asyncio.run(main("--apply" in sys.argv))
