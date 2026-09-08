"""Integration tests for POST /v1/redeem through the ASGI stack.

The ServiceXAdapter the app invokes is stubbed at the redeem.py module
boundary (see conftest's stub_servicex_backend) — nothing on a real
ServiceX backend is contacted.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from structlog.testing import capture_logs

from servicex_token_service.config import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

    import httpx

    from tests.conftest import ServiceXBackendStub


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _audit_events(cap_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [entry for entry in cap_logs if entry.get("event") == "audit"]


@pytest.mark.usefixtures("stub_servicex_backend")
class TestHappyPath:
    async def test_returns_access_token_and_expires_in(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        stub_servicex_backend: ServiceXBackendStub,
    ) -> None:
        resp = await client.post(
            "/v1/redeem",
            json={"refresh_token": "the-refresh-token"},
            headers=_auth(make_token()),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["access_token"] == stub_servicex_backend.access_token
        assert body["expires_in"] > 0

    async def test_refresh_token_reaches_the_stubbed_backend(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        stub_servicex_backend: ServiceXBackendStub,
    ) -> None:
        resp = await client.post(
            "/v1/redeem",
            json={"refresh_token": "the-refresh-token"},
            headers=_auth(make_token()),
        )
        assert resp.status_code == 200
        assert stub_servicex_backend.received_refresh_token == "the-refresh-token"

    async def test_audit_line_carries_required_fields(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        with capture_logs() as cap_logs:
            resp = await client.post(
                "/v1/redeem",
                json={"refresh_token": "the-refresh-token"},
                headers={**_auth(make_token()), "X-Request-ID": "req-42"},
            )
        assert resp.status_code == 200
        (audit,) = _audit_events(cap_logs)
        assert audit["subject"] == "af-user-subject"
        assert audit["jti"]
        assert audit["outcome"] == "issued"
        assert audit["request_id"] == "req-42"

    async def test_no_log_line_ever_contains_a_token(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        broker_token = make_token()
        refresh_token = "the-super-secret-servicex-refresh-token"
        with capture_logs() as cap_logs:
            resp = await client.post(
                "/v1/redeem",
                json={"refresh_token": refresh_token},
                headers=_auth(broker_token),
            )
        assert resp.status_code == 200
        access_token = resp.json()["access_token"]
        logged = repr(cap_logs)
        assert refresh_token not in logged
        assert broker_token not in logged
        assert access_token not in logged


class TestAuthenticationFailures:
    async def test_missing_authorization_header_is_401(
        self, client: httpx.AsyncClient
    ) -> None:
        resp = await client.post("/v1/redeem", json={"refresh_token": "irrelevant"})
        assert resp.status_code == 401

    async def test_expired_token_is_401(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/redeem",
            json={"refresh_token": "irrelevant"},
            headers=_auth(make_token(expires_in=-60)),
        )
        assert resp.status_code == 401
        assert resp.headers["WWW-Authenticate"] == "Bearer"

    async def test_wrong_audience_is_401(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/redeem",
            json={"refresh_token": "irrelevant"},
            headers=_auth(make_token(audience="not-us")),
        )
        assert resp.status_code == 401

    async def test_wrong_issuer_is_401(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/redeem",
            json={"refresh_token": "irrelevant"},
            headers=_auth(make_token(issuer="https://evil.example")),
        )
        assert resp.status_code == 401

    async def test_denied_request_is_audited(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        with capture_logs() as cap_logs:
            await client.post(
                "/v1/redeem",
                json={"refresh_token": "irrelevant"},
                headers=_auth(make_token(expires_in=-60)),
            )
        (audit,) = _audit_events(cap_logs)
        assert audit["outcome"] == "denied"


class TestBadRefreshToken:
    async def test_bad_refresh_token_is_400_not_401(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        stub_servicex_backend: ServiceXBackendStub,
    ) -> None:
        """The identity token is valid; it's the body's ServiceX refresh token that's bad."""
        stub_servicex_backend.outcome = "bad_refresh_token"
        with capture_logs() as cap_logs:
            resp = await client.post(
                "/v1/redeem",
                json={"refresh_token": "bad-token"},
                headers=_auth(make_token()),
            )
        assert resp.status_code == 400
        (audit,) = _audit_events(cap_logs)
        assert audit["outcome"] == "denied"


class TestBackendFailure:
    async def test_backend_unreachable_is_502(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        stub_servicex_backend: ServiceXBackendStub,
    ) -> None:
        stub_servicex_backend.outcome = "unreachable"
        with capture_logs() as cap_logs:
            resp = await client.post(
                "/v1/redeem",
                json={"refresh_token": "some-token"},
                headers=_auth(make_token()),
            )
        assert resp.status_code == 502
        (audit,) = _audit_events(cap_logs)
        assert audit["outcome"] == "error"


@pytest.mark.usefixtures("stub_servicex_backend")
class TestRateLimit:
    async def test_over_limit_is_429_with_retry_after(
        self,
        make_client: Callable[[Settings], httpx.AsyncClient],
        make_token: Callable[..., str],
    ) -> None:
        settings = Settings(
            _env_file=None,
            broker_jwks_url="https://broker.test/jwks",
            broker_issuer="https://broker.test",
            rate_limit_max_events=2,
        )
        async with make_client(settings) as client:
            for _ in range(2):
                resp = await client.post(
                    "/v1/redeem",
                    json={"refresh_token": "the-refresh-token"},
                    headers=_auth(make_token()),
                )
                assert resp.status_code == 200
            with capture_logs() as cap_logs:
                resp = await client.post(
                    "/v1/redeem",
                    json={"refresh_token": "the-refresh-token"},
                    headers=_auth(make_token()),
                )
        assert resp.status_code == 429
        assert int(resp.headers["Retry-After"]) >= 1
        (audit,) = _audit_events(cap_logs)
        assert audit["outcome"] == "denied"

    async def test_rate_limit_is_per_subject(
        self,
        make_client: Callable[[Settings], httpx.AsyncClient],
        make_token: Callable[..., str],
    ) -> None:
        settings = Settings(
            _env_file=None,
            broker_jwks_url="https://broker.test/jwks",
            broker_issuer="https://broker.test",
            rate_limit_max_events=1,
        )
        async with make_client(settings) as client:
            first = await client.post(
                "/v1/redeem",
                json={"refresh_token": "the-refresh-token"},
                headers=_auth(make_token(sub="subject-a")),
            )
            other = await client.post(
                "/v1/redeem",
                json={"refresh_token": "the-refresh-token"},
                headers=_auth(make_token(sub="subject-b")),
            )
        assert first.status_code == 200
        assert other.status_code == 200
