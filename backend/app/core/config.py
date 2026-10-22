from typing import List

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "TrustVault"
    APP_ENV: str = Field(
        default="development",
        description="development | testing | production",
    )
    LOG_LEVEL: str = "INFO"
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Security & Cryptography
    SECRET_KEY: str = Field(
        default="trustvault-insecure-development-secret-key-32-bytes-minimum!",
        min_length=32,
        description="Cryptographic secret key for signing JWTs. Must be >= 32 chars.",
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database URLs
    DATABASE_ADMIN_URL: str = Field(
        default="postgresql+asyncpg://trustvault_admin:admin_password_change_me@localhost:5432/trustvault"
    )
    DATABASE_ADMIN_SYNC_URL: str = Field(
        default="postgresql+psycopg://trustvault_admin:admin_password_change_me@localhost:5432/trustvault"
    )
    DATABASE_APP_URL: str = Field(
        default="postgresql+asyncpg://trustvault_app:app_password_change_me@localhost:5432/trustvault"
    )
    DATABASE_APP_SYNC_URL: str = Field(
        default="postgresql+psycopg://trustvault_app:app_password_change_me@localhost:5432/trustvault"
    )

    # Test Database URLs
    TEST_DATABASE_URL: str = Field(
        default="postgresql+asyncpg://trustvault_app:app_password_change_me@localhost:5432/trustvault_test"
    )
    TEST_DATABASE_ADMIN_URL: str = Field(
        default="postgresql+asyncpg://trustvault_admin:admin_password_change_me@localhost:5432/trustvault_test"
    )

    # Private File Storage
    STORAGE_VAULT_PATH: str = "./storage_vault"
    TEST_STORAGE_VAULT_PATH: str = "./test_storage_vault"
    MAX_UPLOAD_SIZE_BYTES: int = 26214400
    ALLOWED_EXTENSIONS: str = "pdf,docx,xlsx,png,jpg,txt,csv"

    @property
    def cors_origins_list(self) -> List[str]:
        return [
            origin.strip().rstrip("/")
            for origin in self.CORS_ORIGINS.split(",")
            if origin.strip()
        ]

    @property
    def allowed_extensions_list(self) -> List[str]:
        return [
            ext.strip().lower()
            for ext in self.ALLOWED_EXTENSIONS.split(",")
            if ext.strip()
        ]

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str, info) -> str:
        env = info.data.get("APP_ENV", "development").strip().lower()

        if env == "production":
            normalized = v.strip().lower()
            known_insecure_values = {
                "trustvault-insecure-development-secret-key-32-bytes-minimum!",
                "change_me",
                "changeme",
                "your_secret_key",
                "your-secret-key",
                "secret",
                "password",
            }

            if normalized in known_insecure_values or "insecure" in normalized:
                raise ValueError(
                    "Production environment cannot use a default or insecure SECRET_KEY"
                )

            if len(v) < 32:
                raise ValueError(
                    "Production SECRET_KEY must be at least 32 characters long"
                )

        return v

    @model_validator(mode="after")
    def validate_production_settings(self):
        if self.APP_ENV.strip().lower() != "production":
            return self

        database_urls = [
            self.DATABASE_ADMIN_URL,
            self.DATABASE_ADMIN_SYNC_URL,
            self.DATABASE_APP_URL,
            self.DATABASE_APP_SYNC_URL,
            self.TEST_DATABASE_URL,
            self.TEST_DATABASE_ADMIN_URL,
        ]

        placeholder_credentials = (
            "admin_password_change_me",
            "app_password_change_me",
            "change_me",
            "your_password",
            "example",
        )

        for url in database_urls:
            if any(value in url.lower() for value in placeholder_credentials):
                raise ValueError(
                    "Production database URLs must not use placeholder credentials"
                )

        return self


settings = Settings()
