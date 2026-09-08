"""Tests for redeem.py."""

from __future__ import annotations

import asyncio
import time

import jwt
import pytest
from servicex.servicex_adapter import AuthorizationError

from servicex_token_service.config import Settings
from servicex_token_service.redeem import BadRefreshTokenError, RedeemError, redeem


def _make_access_token(exp_in: int = 600) -> str:
    # Key content is irrelevant (redeem.py never verifies this token's
    # signature) but must be >=32 bytes to avoid InsecureKeyLengthWarning.
    return jwt.encode(
        {"exp": int(time.time()) + exp_in, "sub": "servicex-user"},
        "irrelevant-since-unverified-but-long-enough",
        algorithm="HS256",
    )


class TestRedeem:
    async def test_returns_access_token_and_expires_in(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(
            _env_file=None, servicex_backend_url="https://sx.example.com"
        )
        access_token = _make_access_token(exp_in=600)

        class FakeAdapter:
            def __init__(self, url: str, *, refresh_token: str) -> None:
                assert url == "https://sx.example.com"
                assert refresh_token == "the-refresh-token"
                self.token: str | None = None

            async def _get_authorization(self, *, force_reauth: bool) -> dict[str, str]:
                assert force_reauth is True
                self.token = access_token
                return {"Authorization": f"Bearer {access_token}"}

        monkeypatch.setattr(
            "servicex_token_service.redeem.ServiceXAdapter", FakeAdapter
        )
        result = await redeem("the-refresh-token", settings)
        assert result.access_token == access_token
        assert 590 <= result.expires_in <= 600

    async def test_bad_refresh_token_raises_bad_refresh_token_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(
            _env_file=None, servicex_backend_url="https://sx.example.com"
        )

        class FakeAdapter:
            def __init__(self, url: str, *, refresh_token: str) -> None:
                pass

            async def _get_authorization(self, *, force_reauth: bool) -> dict[str, str]:
                raise AuthorizationError(
                    "Not authorized to access serviceX at https://sx.example.com"
                )

        monkeypatch.setattr(
            "servicex_token_service.redeem.ServiceXAdapter", FakeAdapter
        )
        with pytest.raises(BadRefreshTokenError):
            await redeem("bad-token", settings)

    async def test_backend_unreachable_raises_redeem_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(
            _env_file=None, servicex_backend_url="https://sx.example.com"
        )

        class FakeAdapter:
            def __init__(self, url: str, *, refresh_token: str) -> None:
                pass

            async def _get_authorization(self, *, force_reauth: bool) -> dict[str, str]:
                raise TimeoutError("connect timed out")

        monkeypatch.setattr(
            "servicex_token_service.redeem.ServiceXAdapter", FakeAdapter
        )
        with pytest.raises(RedeemError):
            await redeem("some-token", settings)

    async def test_access_token_with_no_exp_claim_uses_default_expiry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(
            _env_file=None, servicex_backend_url="https://sx.example.com"
        )
        access_token = jwt.encode(
            {"sub": "servicex-user"},
            "irrelevant-since-unverified-but-long-enough",
            algorithm="HS256",
        )

        class FakeAdapter:
            def __init__(self, url: str, *, refresh_token: str) -> None:
                self.token: str | None = None

            async def _get_authorization(self, *, force_reauth: bool) -> dict[str, str]:
                self.token = access_token
                return {}

        monkeypatch.setattr(
            "servicex_token_service.redeem.ServiceXAdapter", FakeAdapter
        )
        result = await redeem("token-no-exp", settings)
        assert result.access_token == access_token
        assert result.expires_in > 0  # falls back to a sane default

    async def test_bearer_token_file_env_var_set_raises_redeem_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """This service fails closed if BEARER_TOKEN_FILE is set, as
        defense-in-depth against a future servicex release that might skip
        the refresh-token exchange when it's present (see redeem.py's
        comment — not an active bypass in the installed version, whose
        force_reauth=True path always overwrites it)."""
        settings = Settings(
            _env_file=None, servicex_backend_url="https://sx.example.com"
        )
        monkeypatch.setenv("BEARER_TOKEN_FILE", "/some/path")

        class FakeAdapter:
            def __init__(self, url: str, *, refresh_token: str) -> None:
                pytest.fail("ServiceXAdapter must not be constructed")

        monkeypatch.setattr(
            "servicex_token_service.redeem.ServiceXAdapter", FakeAdapter
        )
        with pytest.raises(RedeemError, match="BEARER_TOKEN_FILE"):
            await redeem("some-token", settings)

    async def test_slow_backend_raises_redeem_error_after_configured_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(
            _env_file=None,
            servicex_backend_url="https://sx.example.com",
            redeem_timeout_seconds=0.05,
        )

        class FakeAdapter:
            def __init__(self, url: str, *, refresh_token: str) -> None:
                self.token: str | None = None

            async def _get_authorization(self, *, force_reauth: bool) -> dict[str, str]:
                await asyncio.sleep(10)
                return {}

        monkeypatch.setattr(
            "servicex_token_service.redeem.ServiceXAdapter", FakeAdapter
        )
        with pytest.raises(RedeemError, match="timed out"):
            await redeem("some-token", settings)
