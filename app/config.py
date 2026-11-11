"""Environment-based configuration.

WHY: Secrets and environment-specific values must come from the environment
(not from source code) so they never end up in Git history or Docker images.
"""
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APP_", env_file=".env", extra="ignore")

    env: str = Field(default="production", pattern="^(development|staging|production|test)$")
    # No default on purpose: the app REFUSES to start without a secret.
    secret_key: str = Field(min_length=32)
    db_path: str = "data/app.db"
    token_ttl_minutes: int = Field(default=30, ge=1, le=1440)
    token_issuer: str = "secure-cicd-demo"
    # Explicit allow-list; an empty list means CORS is disabled (safest default).
    cors_origins: list[str] = []

    @field_validator("cors_origins")
    @classmethod
    def no_wildcard_cors(cls, v: list[str]) -> list[str]:
        if "*" in v:
            raise ValueError("Wildcard CORS origin is not allowed")
        return v

    @property
    def is_production(self) -> bool:
        return self.env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
