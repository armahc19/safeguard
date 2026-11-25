import pytest
from pydantic import SecretStr, ValidationError

from app.core.config import Settings


def test_production_rejects_console_sms_sender():
    with pytest.raises(ValidationError, match="SMS_PROVIDER"):
        Settings(environment="production", secret_key=SecretStr("x" * 40))


def test_http_sms_sender_requires_url():
    with pytest.raises(ValidationError, match="SMS_API_URL"):
        Settings(sms_provider="http", sms_api_token=SecretStr("token"))


def test_development_defaults_to_console_sms():
    settings = Settings(environment="development")
    assert settings.sms_provider == "console"


def test_release_debug_flag_is_treated_as_disabled(monkeypatch):
    monkeypatch.setenv("DEBUG", "release")

    settings = Settings(environment="development")

    assert settings.debug is False
