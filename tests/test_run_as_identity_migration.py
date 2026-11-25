"""Migration 046: immutable managed-execution identities."""

import os
import sqlite3
import subprocess
import sys
import uuid

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from openhands.automation.models import Automation, AutomationGitSyncOrgConfig


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _alembic(db_url: str, *args: str) -> None:
    env = os.environ.copy()
    env["AUTOMATION_DB_URL"] = db_url
    result = subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        env=env,
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )
    assert result.returncode == 0, f"alembic {args} failed: {result.stderr}"


def test_run_as_identity_columns_upgrade_from_045(tmp_path):
    db_path = str(tmp_path / "run_as_identity.db")
    db_url = f"sqlite:///{db_path}"
    _alembic(db_url, "upgrade", "045")

    automation_id = uuid.uuid4()
    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    with sqlite3.connect(db_path) as con:
        con.execute(
            "INSERT INTO automations (id, user_id, org_id, created_by_user_id, name,"
            " trigger, tarball_path, entrypoint, enabled, run_as_kind)"
            " VALUES (?,?,?,?,?,?,?,?,1,?)",
            (
                automation_id.hex,
                user_id.hex,
                org_id.hex,
                user_id.hex,
                "legacy",
                "{}",
                "s3://bucket/code.tar.gz",
                "run",
                "USER",
            ),
        )
        con.execute(
            "INSERT INTO automation_git_sync_org_config"
            " (org_id, overrides, configured_by_user_id)"
            " VALUES (?,?,?)",
            (org_id.hex, "{}", user_id.hex),
        )

    _alembic(db_url, "upgrade", "head")

    engine = create_engine(db_url)
    with Session(engine) as session:
        automation = session.scalars(select(Automation)).one()
        assert automation.run_as_identity_provider is None
        automation.run_as_identity_provider = "entra"
        automation.run_as_identity_tenant_id = "tenant-1"
        automation.run_as_identity_subject_id = "object-1"

        config = session.scalars(select(AutomationGitSyncOrgConfig)).one()
        assert config.configured_by_identity_provider is None
        config.configured_by_identity_provider = "entra"
        config.configured_by_identity_tenant_id = "tenant-1"
        config.configured_by_identity_subject_id = "object-1"
        session.commit()

        session.refresh(automation)
        session.refresh(config)
        assert automation.run_as_identity_subject_id == "object-1"
        assert config.configured_by_identity_subject_id == "object-1"
    engine.dispose()
