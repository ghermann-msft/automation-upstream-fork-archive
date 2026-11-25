"""Migration 045: Sandbox Server execution profile IDs are strings."""

import os
import sqlite3
import subprocess
import sys
import uuid

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from openhands.automation.models import Automation


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


def test_uuid_execution_profile_migrates_to_string_and_accepts_slug(tmp_path):
    db_path = str(tmp_path / "execution_profile.db")
    db_url = f"sqlite:///{db_path}"
    _alembic(db_url, "upgrade", "044")

    automation_id = uuid.uuid4()
    selected = uuid.uuid4()
    with sqlite3.connect(db_path) as con:
        con.execute(
            "INSERT INTO automations (id, user_id, org_id, created_by_user_id, name,"
            " trigger, tarball_path, entrypoint, enabled, run_as_kind,"
            " execution_profile_id) VALUES (?,?,?,?,?,?,?,?,1,?,?)",
            (
                automation_id.hex,
                uuid.uuid4().hex,
                uuid.uuid4().hex,
                uuid.uuid4().hex,
                "legacy",
                "{}",
                "s3://bucket/code.tar.gz",
                "run",
                "USER",
                selected.hex,
            ),
        )

    _alembic(db_url, "upgrade", "head")

    engine = create_engine(db_url)
    with Session(engine) as session:
        automation = session.scalars(select(Automation)).one()
        assert automation.execution_profile_id == selected.hex
        automation.execution_profile_id = "openhands-pool"
        session.commit()
        session.refresh(automation)
        assert automation.execution_profile_id == "openhands-pool"
    engine.dispose()
