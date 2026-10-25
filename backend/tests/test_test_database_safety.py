import os
import subprocess
import sys


def run_conftest_with_database_url(database_url: str):
    env = os.environ.copy()
    env["APP_ENV"] = "testing"
    env["TEST_DATABASE_URL"] = database_url

    return subprocess.run(
        [
            sys.executable,
            "-c",
            "import tests.conftest",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_test_fixture_rejects_production_database():
    result = run_conftest_with_database_url(
        "postgresql+asyncpg://trustvault_app:dummy@localhost:5432/trustvault"
    )

    assert result.returncode != 0
    assert (
        "PostgreSQL tests must use 'trustvault_test'"
        in result.stderr
    )


def test_test_fixture_rejects_wrong_postgres_user():
    result = run_conftest_with_database_url(
        "postgresql+asyncpg://trustvault_admin:dummy@localhost:5432/trustvault_test"
    )

    assert result.returncode != 0
    assert (
        "PostgreSQL tests must use 'trustvault_app'"
        in result.stderr
    )