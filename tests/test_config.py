"""Unit tests for Settings (env-driven configuration)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from servicex_token_service.config import Settings, get_settings


class TestDefaults:
    def test_expected_audience_defaults_to_service_name(self) -> None:
        assert Settings(_env_file=None).expected_audience == "servicex-token-service"

    def test_broker_jwks_url_default(self) -> None:
        assert (
            Settings(_env_file=None).broker_jwks_url
            == "http://localhost:8080/.well-known/jwks.json"
        )

    def test_broker_issuer_default(self) -> None:
        assert Settings(_env_file=None).broker_issuer == "https://mcp.af.uchicago.edu"

    def test_servicex_backend_url_default(self) -> None:
        assert (
            Settings(_env_file=None).servicex_backend_url
            == "https://servicex.example.org"
        )

    def test_redeem_timeout_seconds_default(self) -> None:
        assert Settings(_env_file=None).redeem_timeout_seconds == 10.0

    def test_rate_limit_defaults(self) -> None:
        settings = Settings(_env_file=None)
        assert settings.rate_limit_max_events == 30
        assert settings.rate_limit_window_seconds == 300.0

    def test_jwks_cache_ttl_default(self) -> None:
        assert Settings(_env_file=None).jwks_cache_ttl_seconds == 300

    def test_log_level_default(self) -> None:
        assert Settings(_env_file=None).log_level == "INFO"


class TestRedeemTimeoutInvariant:
    """A non-positive redeem timeout must be rejected at construction time.

    A ServiceX backend that never responds must not hang the request
    forever — see redeem_timeout_seconds' docstring. A zero or negative
    timeout would make that guarantee meaningless, so it is rejected here
    rather than left to fail confusingly wherever the timeout is applied.
    """

    @pytest.mark.parametrize("timeout", [0, -1, -10.0])
    def test_non_positive_timeout_is_rejected(self, timeout: float) -> None:
        with pytest.raises(ValidationError):
            Settings(_env_file=None, redeem_timeout_seconds=timeout)


class TestEnvOverrides:
    def test_env_vars_override_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BROKER_JWKS_URL", "https://broker.example/jwks")
        monkeypatch.setenv("BROKER_ISSUER", "https://broker.example")
        monkeypatch.setenv("EXPECTED_AUDIENCE", "other-audience")
        monkeypatch.setenv("SERVICEX_BACKEND_URL", "https://sx.example.org")
        monkeypatch.setenv("REDEEM_TIMEOUT_SECONDS", "5")
        monkeypatch.setenv("RATE_LIMIT_MAX_EVENTS", "5")
        monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "10")
        monkeypatch.setenv("JWKS_CACHE_TTL_SECONDS", "60")
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")

        settings = Settings(_env_file=None)
        assert settings.broker_jwks_url == "https://broker.example/jwks"
        assert settings.broker_issuer == "https://broker.example"
        assert settings.expected_audience == "other-audience"
        assert settings.servicex_backend_url == "https://sx.example.org"
        assert settings.redeem_timeout_seconds == 5.0
        assert settings.rate_limit_max_events == 5
        assert settings.rate_limit_window_seconds == 10.0
        assert settings.jwks_cache_ttl_seconds == 60
        assert settings.log_level == "DEBUG"


def test_get_settings_is_cached() -> None:
    assert get_settings() is get_settings()
