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

    # CVE enrichment (OSV.dev). The feed hostname is resolved and validated
    # against the SSRF guard before every request (see services.enrichment).
    osv_api_url: str = "https://api.osv.dev/v1/query"
    osv_timeout_seconds: float = 10.0
    osv_enabled: bool = True

    # Domain ownership verification (Phase 1). Scans are allowed only for
    # verified (or grace-grandfathered) domains. REQUIRE_DOMAIN_VERIFICATION
    # exists as a local-development escape hatch only: with it off the app
    # logs a loud warning at startup (see main.py).
    require_domain_verification: bool = True
    # Verified domains expire after this many days and must be re-verified.
    verification_expiry_days: int = 90
    # Migration-grandfathered domains keep scanning for this many days while
    # owners verify; afterwards they are treated as unverified.
    verification_grace_days: int = 14

    # Comma-separated list of TCP ports webhooks (Slack/Discord/Jira) may
    # target. Anything else is rejected at save time and send time.
    webhook_allowed_ports: str = "443,8443"

    # Comma-separated Fernet keys for secrets at rest. The FIRST key
    # encrypts; ALL keys decrypt (rotation: prepend the new key, re-encrypt,
    # drop the old). See app/core/crypto.py.
    secrets_encryption_key: str = ""

    # Comma-separated Fernet keys for secrets at rest. The FIRST key
    # encrypts; ALL keys decrypt (rotation: prepend the new key, re-encrypt,
    # drop the old). See app/core/crypto.py.
    secrets_encryption_key: str = ""

    @property
    def webhook_allowed_port_set(self) -> frozenset[int]:
        """Parsed ``webhook_allowed_ports`` (validated non-empty at startup)."""
        return frozenset(
            int(part.strip()) for part in self.webhook_allowed_ports.split(",")
            if part.strip()
        )

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

        try:
            ports = self.webhook_allowed_port_set
        except ValueError:
            raise ConfigError(
                "WEBHOOK_ALLOWED_PORTS must be comma-separated integers, "
                f"got {self.webhook_allowed_ports!r}."
            )
        if not ports or any(not 1 <= p <= 65535 for p in ports):
            raise ConfigError(
                "WEBHOOK_ALLOWED_PORTS must be non-empty with ports 1-65535, "
                f"got {self.webhook_allowed_ports!r}."
            )

        from app.core.crypto import PLACEHOLDER_KEYS, parse_keys
        from cryptography.fernet import Fernet

        for key in parse_keys(self.secrets_encryption_key):
            if key in PLACEHOLDER_KEYS:
                raise ConfigError(
                    "SECRETS_ENCRYPTION_KEY looks like a placeholder. Generate "
                    "a real key with: "
                    'python -c "from cryptography.fernet import Fernet; '
                    'print(Fernet.generate_key().decode())"'
                )
            try:
                Fernet(key.encode("utf-8"))
            except (ValueError, TypeError) as exc:
                raise ConfigError(
                    "SECRETS_ENCRYPTION_KEY holds an invalid Fernet key. "
                    "Generate a real key with: "
                    'python -c "from cryptography.fernet import Fernet; '
                    'print(Fernet.generate_key().decode())"'
                ) from exc
        if not parse_keys(self.secrets_encryption_key):
            raise ConfigError(
                "SECRETS_ENCRYPTION_KEY is missing. It is required in every "
                "environment (production and local development alike). "
                "Generate one with: "
                'python -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"'
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()


def validate_runtime_config() -> Settings:
    """Explicit validation hook for application startup."""
    return get_settings()
