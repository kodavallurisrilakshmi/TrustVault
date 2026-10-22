import pytest
from httpx import AsyncClient
from app.core.config import Settings


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
