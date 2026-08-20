from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = (
        "postgresql+psycopg://security_monitor:change-me@localhost:5432/security_monitor"
    )
    log_level: str = "INFO"
    rules_path: str | None = None
    assets_path: str | None = None
    auth_required: bool = False
    admin_username: str = "admin"
    admin_password_hash: str = ""
    admin_session_secret: str = ""
    admin_session_ttl_minutes: int = 60
    admin_login_rate_limit_per_minute: int = 10
    cors_origins: list[str] = Field(default_factory=list)
    collector_credential_ttl_days: int = 365
    collector_max_batch_size: int = 500
    collector_max_body_bytes: int = 2_000_000
    collector_max_clock_skew_seconds: int = 900
    collector_rate_limit_per_minute: int = 120

    model_config = SettingsConfigDict(
        env_file="../.env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
