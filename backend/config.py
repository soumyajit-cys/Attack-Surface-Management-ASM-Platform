import secrets

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    app_name: str = "SentinelASM"

    debug: bool = False

    api_prefix: str = ""

    database_url: str = (
        "postgresql://sentinel:sentinelpass@localhost:5432/sentinelasm"
    )

    redis_url: str = "redis://localhost:6379/0"

    jwt_secret: str = (
        "dev-only-insecure-secret-replace-me"
    )

    jwt_algorithm: str = "HS256"

    access_token_expire_minutes: int = 15

    refresh_token_expire_days: int = 7

    smtp_host: str = ""

    smtp_port: int = 587

    smtp_user: str = ""

    smtp_password: str = ""

    smtp_from: str = "sentinelasm@example.com"

    frontend_url: str = "http://localhost:5173"

    @property
    def jwt_secret_for_use(self) -> str:
        if (
            self.jwt_secret
            == "dev-only-insecure-secret-replace-me"
        ):
            return secrets.token_hex(32)
        return self.jwt_secret


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()