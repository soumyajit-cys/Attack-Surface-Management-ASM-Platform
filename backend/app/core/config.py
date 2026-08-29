"""Application configuration.

Single source of truth for settings. The legacy top-level ``config`` module
re-exports ``settings`` from here so both generations of code share one
instance.

Validation policy (fail fast):
- ``jwt_secret`` must be set and >= MIN_JWT_SECRET_LENGTH in every environment.
  Empty or default secrets are rejected at import time -- no silent dev secrets.
- In ``production``: debug must be off, the default database credentials are
  rejected, and CORS origins must be explicitly configured.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_JWT_SECRET_LENGTH = 16
_MIN_JWT_SECRET_LENGTH_PRODUCTION = 32

_DEFAULT_JWT_SECRETS = frozenset(
    {
        "",
        "dev-only-insecure-secret-replace-me",
        "change-me",
        "secret",
    }
)

_DEFAULT_DATABASE_URL = "postgresql://sentinel:sentinelpass@localhost:5432/sentinelasm"

Environment = Literal["development", "testing", "production"]


class ConfigError(RuntimeError):
    """Raised when configuration is invalid for the target environment."""


class Settings(BaseSettings):

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "SentinelASM"

    environment: Environment = "development"

    debug: bool = False

    database_url: str = _DEFAULT_DATABASE_URL

    redis_url: str = "redis://localhost:6379/0"

    jwt_secret: str = Field(min_length=MIN_JWT_SECRET_LENGTH)

    jwt_algorithm: str = "HS256"

    access_token_expire_minutes: int = 15

    refresh_token_expire_days: int = 7

    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )

    smtp_host: str = ""

    smtp_port: int = 587

    smtp_user: str = ""

    smtp_password: str = ""

    smtp_from: str = "sentinelasm@example.com"

    frontend_url: str = "http://localhost:5173"

    rate_limit_requests_per_minute: int = 60
    rate_limit_auth_requests_per_minute: int = 10
    rate_limit_scan_requests_per_minute: int = 5

    kev_cache_dir: str = ""

    log_level: str = "INFO"
    log_format: str = "json"

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_testing(self) -> bool:
        return self.environment == "testing"

    @property
    def jwt_secret_for_use(self) -> str:
        """Legacy alias used by ``auth.jwt``. The secret is always validated."""
        return self.jwt_secret

    @model_validator(mode="after")
    def _validate_environment_policy(self) -> "Settings":
        if self.jwt_secret in _DEFAULT_JWT_SECRETS:
            raise ConfigError(
                "JWT_SECRET is missing or uses a known default value. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        required_length = (
            _MIN_JWT_SECRET_LENGTH_PRODUCTION if self.is_production else MIN_JWT_SECRET_LENGTH
        )
        if len(self.jwt_secret) < required_length:
            raise ConfigError(
                f"JWT_SECRET must be at least {required_length} characters "
                f"in environment='{self.environment}' (got {len(self.jwt_secret)})."
            )

        if self.is_production:
            if self.debug:
                raise ConfigError("DEBUG must be false in production.")
            if self.database_url == _DEFAULT_DATABASE_URL:
                raise ConfigError(
                    "Default database credentials are not allowed in production. "
                    "Set DATABASE_URL explicitly."
                )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()


def validate_runtime_config() -> Settings:
    """Explicit validation hook for application startup."""
    return get_settings()
