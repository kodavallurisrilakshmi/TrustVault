import pytest
from pathlib import Path
from httpx import AsyncClient
from app.core.config import Settings
from app.main import check_vault_writable


@pytest.mark.asyncio
async def test_liveness_health_check(client: AsyncClient):
    """Verify /health returns 200 OK and service identifier."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "TrustVault"


@pytest.mark.asyncio
async def test_readiness_health_check(client: AsyncClient):
    """Verify /health/ready checks database connection and storage vault directory."""
    response = await client.get("/health/ready")
    assert response.status_code in (200, 503)
    data = response.json()
    assert "database" in data
    assert "vault" in data


def test_check_vault_writable_for_writable_directory(tmp_path):
    """A writable vault directory should pass the storage check."""
    assert check_vault_writable(tmp_path) is True

    # The temporary health-check file should be removed.
    assert list(tmp_path.iterdir()) == []


def test_check_vault_writable_for_missing_directory(tmp_path):
    """A missing vault directory should fail the storage check."""
    missing_path = tmp_path / "missing-vault"

    assert check_vault_writable(missing_path) is False


def test_check_vault_writable_for_file_path(tmp_path):
    """A regular file is not a valid vault directory."""
    file_path = tmp_path / "not-a-directory"
    file_path.write_text("test", encoding="utf-8")

    assert check_vault_writable(file_path) is False


@pytest.mark.asyncio
async def test_config_check_masks_secrets(client: AsyncClient):
    """Verify /health/config does not leak SECRET_KEY or database passwords."""
    response = await client.get("/health/config")
    assert response.status_code == 200
    data = response.json()
    assert "SECRET_KEY" not in data
    assert "DATABASE_ADMIN_URL" not in data
    assert "DATABASE_APP_URL" not in data
    assert "app_name" in data
    assert data["app_name"] == "TrustVault"


@pytest.mark.asyncio
async def test_config_check_does_not_expose_storage_path(client: AsyncClient):
    """Public config must not reveal the private vault filesystem location."""
    from app.core.config import settings

    response = await client.get("/health/config")
    assert response.status_code == 200
    data = response.json()
    serialized = response.text.lower()

    assert "storage_vault_path" not in data
    assert "STORAGE_VAULT_PATH" not in data
    assert "storage_vault_path" not in serialized
    assert settings.STORAGE_VAULT_PATH.lower() not in serialized
    assert settings.TEST_STORAGE_VAULT_PATH.lower() not in serialized
    assert "app_name" in data
    assert "max_upload_size_bytes" in data
    assert "allowed_extensions" in data


def test_production_environment_rejects_insecure_secret_key():
    """Verify Settings validator raises ValueError if production environment has default insecure secret."""
    with pytest.raises(
    ValueError,
    match="Production environment cannot use a default or insecure SECRET_KEY",
):
        Settings(
            APP_ENV="production",
            SECRET_KEY="trustvault-insecure-development-secret-key-32-bytes-minimum!"
        )


def test_production_rejects_default_database_credentials():
    """Production must reject placeholder database passwords."""
    with pytest.raises(
        ValueError,
        match="Production database URLs must not use placeholder credentials",
    ):
        Settings(
            APP_ENV="production",
            SECRET_KEY="a-strong-production-secret-key-with-more-than-32-chars",
        )


def test_development_allows_default_database_credentials():
    """Development should remain usable with local placeholder credentials."""
    config = Settings(
        APP_ENV="development",
        SECRET_KEY="a-development-secret-key-with-more-than-32-chars",
    )
    assert config.APP_ENV == "development"

def test_production_rejects_weak_secret_key():
    with pytest.raises(ValueError):
        Settings(
            APP_ENV="production",
            SECRET_KEY="this-is-a-weak-key-without-insecure",
        )

def test_production_rejects_invalid_environment_name():
    """Unknown environment names should not silently select a configuration."""
    with pytest.raises(ValueError):
        Settings(
            APP_ENV="prodution",
            SECRET_KEY="a-development-secret-key-with-more-than-32-chars",
        )


def test_production_requires_explicit_non_localhost_cors_origins():
    """Production must reject localhost frontend origins specifically."""
    with pytest.raises(
        ValueError,
        match="Production CORS origins must use HTTPS and must not use localhost",
    ):
        Settings(
            APP_ENV="production",
            STORAGE_VAULT_PATH=str(Path("C:/trustvault-test-vault")),
            SECRET_KEY="a-strong-production-secret-key-with-more-than-32-chars",
            CORS_ORIGINS="http://localhost:5173,http://127.0.0.1:5173",
            DATABASE_ADMIN_URL="postgresql+asyncpg://admin:real-password@db.trustvault.internal:5432/trustvault?ssl=verify-full",
            DATABASE_ADMIN_SYNC_URL="postgresql+psycopg://admin:real-password@db.trustvault.internal:5432/trustvault?sslmode=verify-full",
            DATABASE_APP_URL="postgresql+asyncpg://app:real-password@db.trustvault.internal:5432/trustvault?ssl=verify-full",
            DATABASE_APP_SYNC_URL="postgresql+psycopg://app:real-password@db.trustvault.internal:5432/trustvault?sslmode=verify-full",
            TEST_DATABASE_URL="postgresql+asyncpg://app:real-password@localhost:5432/trustvault_test",
            TEST_DATABASE_ADMIN_URL="postgresql+asyncpg://admin:real-password@localhost:5432/trustvault_test",
        )



def test_production_does_not_require_test_database_credentials():
    """Production validation should not depend on test database credentials."""
    config = Settings(
        APP_ENV="production",
        STORAGE_VAULT_PATH=str(Path("C:/trustvault-test-vault")),
        SECRET_KEY="a-strong-production-secret-key-with-more-than-32-chars",
        CORS_ORIGINS="https://trustvault.example.com",
        DATABASE_ADMIN_URL="postgresql+asyncpg://admin:real-password@db.trustvault.internal:5432/trustvault?ssl=verify-full",
        DATABASE_ADMIN_SYNC_URL="postgresql+psycopg://admin:real-password@db.trustvault.internal:5432/trustvault?sslmode=verify-full",
        DATABASE_APP_URL="postgresql+asyncpg://app:real-password@db.trustvault.internal:5432/trustvault?ssl=verify-full",
        DATABASE_APP_SYNC_URL="postgresql+psycopg://app:real-password@db.trustvault.internal:5432/trustvault?sslmode=verify-full",
        TEST_DATABASE_URL="postgresql+asyncpg://app:app_password_change_me@localhost:5432/trustvault_test",
        TEST_DATABASE_ADMIN_URL="postgresql+asyncpg://admin:admin_password_change_me@localhost:5432/trustvault_test",
    )

    assert config.APP_ENV == "production"

def test_production_environment_normalization():
    """Environment validation should normalize case and whitespace."""
    import pytest

    from app.core.config import Settings

    with pytest.raises(
        ValueError,
        match="Production environment cannot use a default or insecure SECRET_KEY",
    ):
        Settings(
            APP_ENV="Production",
            SECRET_KEY="trustvault-insecure-development-secret-key-32-bytes-minimum!",
        )


def test_production_rejects_loopback_database_address():
    """Production must reject loopback IP literals in database URLs."""
    with pytest.raises(
        ValueError,
        match="localhost or loopback addresses",
    ):
        Settings(
            APP_ENV="production",
            STORAGE_VAULT_PATH="C:/trustvault-test-vault",
            SECRET_KEY="a-strong-production-secret-key-with-more-than-32-chars",
            CORS_ORIGINS="https://trustvault.example.com",
            DATABASE_ADMIN_URL=(
                "postgresql+asyncpg://admin:real-password@127.0.0.1:5432/trustvault"
            ),
            DATABASE_ADMIN_SYNC_URL=(
                "postgresql+psycopg://admin:real-password@db.trustvault.internal:5432/trustvault"
            ),
            DATABASE_APP_URL=(
                "postgresql+asyncpg://app:real-password@db.trustvault.internal:5432/trustvault"
            ),
            DATABASE_APP_SYNC_URL=(
                "postgresql+psycopg://app:real-password@db.trustvault.internal:5432/trustvault"
            ),
        )
def test_production_rejects_ipv6_loopback_database_address():
    """Production must reject IPv6 loopback database addresses."""
    with pytest.raises(
        ValueError,
        match="localhost or loopback addresses",
    ):
        Settings(
            APP_ENV="production",
            STORAGE_VAULT_PATH="C:/trustvault-test-vault",
            SECRET_KEY="a-strong-production-secret-key-with-more-than-32-chars",
            CORS_ORIGINS="https://trustvault.example.com",
            DATABASE_ADMIN_URL=(
                "postgresql+asyncpg://admin:real-password@[::1]:5432/trustvault"
            ),
            DATABASE_ADMIN_SYNC_URL=(
                "postgresql+psycopg://admin:real-password@db.trustvault.internal:5432/trustvault"
            ),
            DATABASE_APP_URL=(
                "postgresql+asyncpg://app:real-password@db.trustvault.internal:5432/trustvault"
            ),
            DATABASE_APP_SYNC_URL=(
                "postgresql+psycopg://app:real-password@db.trustvault.internal:5432/trustvault"
            ),
        )


def test_production_rejects_placeholder_database_hostname():
    """Production must reject an example hostname used as a placeholder."""
    with pytest.raises(ValueError):
        Settings(
            APP_ENV="production",
            STORAGE_VAULT_PATH="C:/trustvault-test-vault",
            SECRET_KEY="a-strong-production-secret-key-with-more-than-32-chars",
            CORS_ORIGINS="https://trustvault.example.com",
            DATABASE_ADMIN_URL=(
                "postgresql+asyncpg://admin:real-password@example.com:5432/trustvault"
            ),
            DATABASE_ADMIN_SYNC_URL=(
                "postgresql+psycopg://admin:real-password@db.trustvault.internal:5432/trustvault"
            ),
            DATABASE_APP_URL=(
                "postgresql+asyncpg://app:real-password@db.trustvault.internal:5432/trustvault"
            ),
            DATABASE_APP_SYNC_URL=(
                "postgresql+psycopg://app:real-password@db.trustvault.internal:5432/trustvault"
            ),
        )

def test_production_rejects_database_urls_without_tls():
    """Production database URLs must explicitly enable TLS."""
    with pytest.raises(ValueError, match="TLS"):
        Settings(
            APP_ENV="production",
            STORAGE_VAULT_PATH="C:/trustvault-test-vault",
            SECRET_KEY="a-strong-production-secret-key-with-more-than-32-chars",
            CORS_ORIGINS="https://trustvault.example.com",
            DATABASE_ADMIN_URL=(
                "postgresql+asyncpg://admin:real-password"
                "@db.trustvault.internal:5432/trustvault"
            ),
            DATABASE_ADMIN_SYNC_URL=(
                "postgresql+psycopg://admin:real-password"
                "@db.trustvault.internal:5432/trustvault"
            ),
            DATABASE_APP_URL=(
                "postgresql+asyncpg://app:real-password"
                "@db.trustvault.internal:5432/trustvault"
            ),
            DATABASE_APP_SYNC_URL=(
                "postgresql+psycopg://app:real-password"
                "@db.trustvault.internal:5432/trustvault"
            ),
        )


def test_production_rejects_database_url_without_hostname():
    """Production database URLs must specify a hostname."""
    with pytest.raises(ValueError, match="hostname"):
        Settings(
            APP_ENV="production",
            STORAGE_VAULT_PATH="C:/trustvault-test-vault",
            SECRET_KEY="a-strong-production-secret-key-with-more-than-32-chars",
            CORS_ORIGINS="https://trustvault.example.com",
            DATABASE_ADMIN_URL="postgresql+asyncpg:///trustvault",
            DATABASE_ADMIN_SYNC_URL=(
                "postgresql+psycopg://admin:real-password"
                "@db.trustvault.internal:5432/trustvault?sslmode=verify-full"
            ),
            DATABASE_APP_URL=(
                "postgresql+asyncpg://app:real-password"
                "@db.trustvault.internal:5432/trustvault?ssl=verify-full"
            ),
            DATABASE_APP_SYNC_URL=(
                "postgresql+psycopg://app:real-password"
                "@db.trustvault.internal:5432/trustvault?sslmode=verify-full"
            ),
        )


def test_production_rejects_relative_storage_path():
    """Production storage must use an absolute path."""
    with pytest.raises(ValueError, match="absolute path"):
        Settings(
            APP_ENV="production",
            STORAGE_VAULT_PATH="./storage_vault",
            SECRET_KEY="a-strong-production-secret-key-with-more-than-32-chars",
            CORS_ORIGINS="https://trustvault.example.com",
            DATABASE_ADMIN_URL=(
                "postgresql+asyncpg://admin:real-password"
                "@db.trustvault.internal:5432/trustvault?ssl=verify-full"
            ),
            DATABASE_ADMIN_SYNC_URL=(
                "postgresql+psycopg://admin:real-password"
                "@db.trustvault.internal:5432/trustvault?sslmode=verify-full"
            ),
            DATABASE_APP_URL=(
                "postgresql+asyncpg://app:real-password"
                "@db.trustvault.internal:5432/trustvault?ssl=verify-full"
            ),
            DATABASE_APP_SYNC_URL=(
                "postgresql+psycopg://app:real-password"
                "@db.trustvault.internal:5432/trustvault?sslmode=verify-full"
            ),
        )

def test_production_rejects_test_url_pointing_to_production_database():
    """A test URL must not target the production database."""
    with pytest.raises(
        ValueError,
        match="Test database URLs must not point to the production",
    ):
        Settings(
            APP_ENV="production",
            STORAGE_VAULT_PATH="C:/trustvault-test-vault",
            SECRET_KEY="a-strong-production-secret-key-with-more-than-32-chars",
            CORS_ORIGINS="https://trustvault.example.com",
            DATABASE_ADMIN_URL=(
                "postgresql+asyncpg://admin:real-password"
                "@db.trustvault.internal:5432/trustvault?ssl=verify-full"
            ),
            DATABASE_ADMIN_SYNC_URL=(
                "postgresql+psycopg://admin:real-password"
                "@db.trustvault.internal:5432/trustvault?sslmode=verify-full"
            ),
            DATABASE_APP_URL=(
                "postgresql+asyncpg://app:real-password"
                "@db.trustvault.internal:5432/trustvault?ssl=verify-full"
            ),
            DATABASE_APP_SYNC_URL=(
                "postgresql+psycopg://app:real-password"
                "@db.trustvault.internal:5432/trustvault?sslmode=verify-full"
            ),
            TEST_DATABASE_URL=(
                "postgresql+asyncpg://app:real-password"
                "@db.trustvault.internal:5432/trustvault"
                "_production_backup?ssl=verify-full"
            ),
            TEST_DATABASE_ADMIN_URL=(
                "postgresql+asyncpg://admin:real-password"
                "@db.trustvault.internal:5432/trustvault_test"
            ),
        )
