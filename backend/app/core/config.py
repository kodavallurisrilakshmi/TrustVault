import ipaddress
from pathlib import Path
from typing import List
from urllib.parse import parse_qs, unquote, urlparse

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

    @field_validator("APP_ENV")
    @classmethod
    def validate_app_env(cls, value: str) -> str:
        value = value.strip().lower()
        allowed_environments = {"development", "testing", "production"}

        if value not in allowed_environments:
            raise ValueError(
                "APP_ENV must be development, testing, or production"
            )

        return value

    LOG_LEVEL: str = "INFO"
    CORS_ORIGINS: str = (
        "http://localhost:5173,http://127.0.0.1:5173"
    )

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
    def validate_secret_key(cls, value: str, info) -> str:
        env = info.data.get("APP_ENV", "development").strip().lower()

        if env == "production":
            normalized = value.strip().lower()
            known_insecure_values = {
                "trustvault-insecure-development-secret-key-32-bytes-minimum!",
                "change_me",
                "changeme",
                "your_secret_key",
                "your-secret-key",
                "secret",
                "password",
            }

            if (
                normalized in known_insecure_values
                or "insecure" in normalized
            ):
                raise ValueError(
                    "Production environment cannot use a default or insecure SECRET_KEY"
                )

            if len(value) < 32:
                raise ValueError(
                    "Production SECRET_KEY must be at least 32 characters long"
                )

        return value

    @model_validator(mode="after")
    def validate_production_settings(self):
        if self.APP_ENV != "production":
            return self

        # Require a sufficiently long, nontrivial production secret.
        secret = self.SECRET_KEY.strip()
        if len(secret) < 32 or len(set(secret)) < 16:
            raise ValueError(
                "Production SECRET_KEY must be at least 32 characters "
                "and contain sufficient character diversity"
            )

        database_urls = [
            self.DATABASE_ADMIN_URL,
            self.DATABASE_ADMIN_SYNC_URL,
            self.DATABASE_APP_URL,
            self.DATABASE_APP_SYNC_URL,
        ]

        placeholder_hosts = {
            "localhost",
            "localhost.localdomain",
            "example",
            "example.com",
            "your_host",
            "your-host",
        }

        placeholder_credentials = {
            "change_me",
            "changeme",
            "your_password",
            "your-password",
            "admin_password_change_me",
            "app_password_change_me",
            "password",
            "example",
        }

        production_targets = set()

        # Validate production database URLs.
        for url in database_urls:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").strip().lower()
            username = unquote(parsed.username or "").lower()
            password = unquote(parsed.password or "").lower()
            database_name = parsed.path.lstrip("/").lower()

            # Check credentials before host/TLS so failures are specific.
            if (
                username in placeholder_credentials
                or password in placeholder_credentials
            ):
                raise ValueError(
                    "Production database URLs must not use placeholder credentials"
                )

            if parsed.scheme not in {
                "postgresql+asyncpg",
                "postgresql+psycopg",
            }:
                raise ValueError(
                    "Production database URLs must use a supported PostgreSQL driver"
                )

            if not hostname:
                raise ValueError(
                    "Production database URLs must specify a hostname"
                )

            try:
                ip = ipaddress.ip_address(hostname)
            except ValueError:
                ip = None

            if (
                hostname in {"localhost", "localhost.localdomain"}
                or (ip is not None and (ip.is_loopback or ip.is_unspecified))
            ):
                raise ValueError(
                    "Production database URLs must not use localhost or loopback addresses"
                )

            if (
                hostname in placeholder_hosts
                or hostname.endswith(".example")
                or hostname.endswith(".invalid")
                or hostname.endswith(".test")
            ):
                raise ValueError(
                    "Production database URLs must not use placeholder hostnames"
                )

            query = parse_qs(parsed.query)
            if parsed.scheme == "postgresql+asyncpg":
                tls_values = query.get("ssl", [])
            else:
                tls_values = query.get("sslmode", [])

            if "verify-full" not in {
                value.strip().lower() for value in tls_values
            }:
                raise ValueError(
                    "Production database URLs must enable TLS with certificate verification (verify-full)"
                )

            production_targets.add(
                (hostname, parsed.port or 5432, database_name)
            )

        # Test database URLs must not target production databases.
        test_urls = [
            self.TEST_DATABASE_URL,
            self.TEST_DATABASE_ADMIN_URL,
        ]

        for url in test_urls:
            parsed_test = urlparse(url)
            test_host = (parsed_test.hostname or "").strip().lower()
            test_database = parsed_test.path.lstrip("/").lower()
            test_port = parsed_test.port or 5432

            if any(
    test_host == production_host
    and test_port == production_port
    and (
        test_database == production_database
        or test_database.startswith(production_database + "_")
    )
    for production_host, production_port, production_database in production_targets):
             raise ValueError(
                 "Test database URLs must not point to the production database"
        )

        # Production storage must be an absolute path.
        if not Path(self.STORAGE_VAULT_PATH).is_absolute():
            raise ValueError(
                "Production STORAGE_VAULT_PATH must be an absolute path"
            )

        # Validate production frontend origins.
        for origin in self.cors_origins_list:
            parsed_origin = urlparse(origin)
            hostname = (parsed_origin.hostname or "").strip().lower()

            try:
                ip = ipaddress.ip_address(hostname)
            except ValueError:
                ip = None

            if (
                parsed_origin.scheme != "https"
                or not hostname
                or parsed_origin.username is not None
                or parsed_origin.password is not None
                or parsed_origin.path not in {"", "/"}
                or parsed_origin.query
                or parsed_origin.fragment
                or hostname in {
                    "localhost",
                    "localhost.localdomain",
                }
                or (ip is not None and (ip.is_loopback or ip.is_unspecified))
            ):
                raise ValueError(
                    "Production CORS origins must use HTTPS and must not use localhost"
                )

        return self


settings = Settings()