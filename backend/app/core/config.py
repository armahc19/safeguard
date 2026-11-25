"""Application settings, loaded from environment variables / .env (see .env.example)."""
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_SECRET = "dev-only-secret-change-me-dev-only-secret"
_BACKEND_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_BACKEND_ENV_FILE,
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
    )

    # --- app
    app_name: str = "SafeGuard API"
    environment: Literal["development", "test", "staging", "production"] = "development"
    debug: bool = False
    api_prefix: str = "/v1"
    cors_origins: list[str] = Field(default_factory=list)  # JSON list in env, e.g. '["https://app.example.com"]'
    trusted_hosts: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    security_headers: bool = True
    max_request_body_bytes: int = 1_000_000

    # --- logging
    log_level: str = "INFO"
    log_json: bool = True

    # --- database (async driver; Alembic uses sync_database_url)
    database_url: str = "postgresql+asyncpg://safeguard:safeguard@localhost:5432/safeguard"
    db_pool_size: int = 10
    db_max_overflow: int = 10
    db_pool_recycle_seconds: int = 1800
    db_echo: bool = False

    # --- redis
    redis_url: str = "redis://localhost:6379/0"

    # --- auth
    secret_key: SecretStr = SecretStr(_DEV_SECRET)
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 30

    otp_length: int = 6
    otp_ttl_seconds: int = 300
    otp_max_attempts: int = 5
    otp_requests_per_phone: int = 3  # per 10 minutes
    otp_requests_per_ip: int = 20  # per hour

    # Console is safe for local development only. Production must use a real
    # provider configured through the HTTP sender settings below.
    sms_provider: Literal["console", "http"] = "console"
    sms_api_url: str | None = None
    sms_api_token: SecretStr | None = None
    sms_sender_id: str | None = None

    # Optional shared Gradio/voice generation and speech recognition provider.
    groq_api_key: SecretStr | None = None

    # In-process recurring worker; no second server or external cron is needed.
    awareness_scheduler_enabled: bool = True
    awareness_scheduler_interval_seconds: int = Field(default=300, ge=60, le=86400)

    default_calling_code: str = "233"  # used to expand local numbers like 024xxxxxxx

    # --- fraud intelligence
    reports_per_user_per_day: int = 20
    lookups_per_user_per_minute: int = 60
    duplicate_report_window_hours: int = 24
    behaviour_lookback_days: int = 30
    behaviour_velocity_window_hours: int = 24
    behaviour_velocity_alert_count: int = 5

    # USSD / SMS gateways authenticate with an HMAC secret each, e.g. '{"ussd": "...", "sms": "..."}'
    gateway_secrets: dict[str, SecretStr] = Field(default_factory=dict)
    gateway_timestamp_tolerance_seconds: int = 300

    @field_validator("debug", mode="before")
    @classmethod
    def _parse_debug_flag(cls, value: object) -> object:
        """Accept boolean values and the release-style flags used by hosts.

        Some deployment environments expose ``DEBUG=release`` to indicate a
        non-debug release build.  Pydantic's default boolean parser rejects
        that value before the settings model can validate the rest of the
        configuration, which can mask the actionable error (for example, a
        missing production SMS provider).
        """
        if isinstance(value, str):
            normalised = value.strip().lower()
            if normalised in {"release", "production", "false", "off", "no", "0"}:
                return False
            if normalised in {"debug", "development", "true", "on", "yes", "1"}:
                return True
        return value

    @field_validator("secret_key")
    @classmethod
    def _secret_key_must_not_be_empty(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("SECRET_KEY must not be empty. Set a random signing key in backend/.env.")
        return value

    @property
    def is_production_like(self) -> bool:
        return self.environment in ("staging", "production")

    @property
    def effective_awareness_scheduler_interval_seconds(self) -> int:
        # Development gets minute-level polling so the opt-in test schedule can
        # be observed quickly. Production keeps the configured, lower-frequency poll.
        if self.environment in {"development", "test"}:
            return min(60, self.awareness_scheduler_interval_seconds)
        return self.awareness_scheduler_interval_seconds

    @property
    def sync_database_url(self) -> str:
        """Sync URL for Alembic (psycopg driver)."""
        return self.database_url.replace("+asyncpg", "+psycopg")

    @model_validator(mode="after")
    def _validate_for_environment(self) -> "Settings":
        if self.is_production_like:
            secret = self.secret_key.get_secret_value()
            if secret == _DEV_SECRET or len(secret) < 32:
                raise ValueError("SECRET_KEY must be set to a random value of at least 32 characters")
            if self.debug:
                raise ValueError("DEBUG must be false in staging/production")
            if self.sms_provider == "console":
                raise ValueError("SMS_PROVIDER must not be console in staging/production")
            if not self.trusted_hosts or "*" in self.trusted_hosts:
                raise ValueError("TRUSTED_HOSTS must contain explicit hosts in staging/production")
            if "*" in self.cors_origins:
                raise ValueError("CORS_ORIGINS must not contain '*' in staging/production")
        if self.sms_provider == "http":
            if not self.sms_api_url:
                raise ValueError("SMS_API_URL is required when SMS_PROVIDER=http")
            if not self.sms_api_token:
                raise ValueError("SMS_API_TOKEN is required when SMS_PROVIDER=http")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
