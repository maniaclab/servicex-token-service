"""Shared fixtures: RSA keypair, stubbed JWKS fetch, a broker-token factory,
and a stubbed ServiceX backend + ASGI test client for endpoint tests.

The JWKS is never fetched over the network in tests — ``stub_jwks_fetch``
replaces ``identity._fetch_jwks`` (the single network boundary) with an
in-process stub serving keys generated here. Likewise, the ServiceX backend
is never contacted — ``stub_servicex_backend`` replaces
``redeem.ServiceXAdapter`` (redeem.py's only network boundary) the same way
Task 5's tests did, but shared/reusable across endpoint tests.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import TYPE_CHECKING, Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from servicex.servicex_adapter import AuthorizationError

from servicex_token_service import identity
from servicex_token_service.app import create_app
from servicex_token_service.config import Settings

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

TEST_KID = "test-signing-key"


@pytest.fixture(scope="session")
def rsa_private_key() -> rsa.RSAPrivateKey:
    # 2048 bits keeps per-session generation fast while staying a realistic
    # RS256 key size.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def other_rsa_private_key() -> rsa.RSAPrivateKey:
    """A second keypair NOT in the served JWKS — for wrong-signature tests."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def jwks(rsa_private_key: rsa.RSAPrivateKey) -> list[dict[str, Any]]:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(rsa_private_key.public_key()))
    jwk.update({"kid": TEST_KID, "alg": "RS256", "use": "sig"})
    return [jwk]


@pytest.fixture
def settings() -> Settings:
    return Settings(
        _env_file=None,
        broker_jwks_url="https://broker.test/jwks",
        broker_issuer="https://broker.test",
    )


class JwksFetchStub:
    """Callable standing in for ``identity._fetch_jwks``.

    Counts calls, can be told to fail (mimicking the real fetch's 502), and
    can delay to expose single-flight behavior.
    """

    def __init__(self, keys: list[dict[str, Any]]) -> None:
        self.keys = keys
        self.calls = 0
        self.fail = False
        self.delay = 0.0

    async def __call__(self, jwks_url: str) -> list[dict[str, Any]]:
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            raise HTTPException(
                status_code=502,
                detail=f"Unable to reach JWKS endpoint: {jwks_url}",
            )
        return self.keys


@pytest.fixture
def stub_jwks_fetch(
    jwks: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> JwksFetchStub:
    identity._jwks_cache.clear()
    stub = JwksFetchStub(jwks)
    monkeypatch.setattr(identity, "_fetch_jwks", stub)
    return stub


@pytest.fixture
def make_token(
    rsa_private_key: rsa.RSAPrivateKey, settings: Settings
) -> Callable[..., str]:
    """Factory for AF Broker Identity Tokens with controllable claims."""

    def _make(
        *,
        sub: str = "af-user-subject",
        issuer: str | None = None,
        audience: str | None = None,
        key: rsa.RSAPrivateKey | None = None,
        kid: str | None = TEST_KID,
        expires_in: int = 300,
        omit: tuple[str, ...] = (),
        extra: dict[str, Any] | None = None,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": issuer or settings.broker_issuer,
            "sub": sub,
            "aud": audience or settings.expected_audience,
            "exp": now + expires_in,
            "iat": now,
            "jti": str(uuid.uuid4()),
        }
        if extra:
            claims.update(extra)
        for claim in omit:
            claims.pop(claim, None)
        headers = {"kid": kid} if kid is not None else None
        return jwt.encode(
            claims, key or rsa_private_key, algorithm="RS256", headers=headers
        )

    return _make


def _make_servicex_access_token(expires_in: int = 600) -> str:
    """Mint an unsigned-verification-only access token, mirroring test_redeem.py's helper.

    Key content is irrelevant (redeem.py never verifies this token's
    signature — see redeem.py's _expires_in docstring) but must still be
    >=32 bytes to avoid pytest's InsecureKeyLengthWarning noise.
    """
    return jwt.encode(
        {"exp": int(time.time()) + expires_in, "sub": "servicex-user"},
        "irrelevant-since-unverified-but-long-enough",
        algorithm="HS256",
    )


class _FakeServiceXAdapter:
    """Stands in for the real ServiceXAdapter's ``_get_authorization`` call."""

    def __init__(self, stub: ServiceXBackendStub) -> None:
        self._stub = stub
        self.token: str | None = None

    async def _get_authorization(self, *, force_reauth: bool) -> dict[str, str]:
        assert force_reauth is True
        if self._stub.outcome == "bad_refresh_token":
            raise AuthorizationError(
                "Not authorized to access serviceX at the stubbed backend"
            )
        if self._stub.outcome == "unreachable":
            raise TimeoutError("connect timed out")
        self.token = self._stub.access_token
        return {}


class ServiceXBackendStub:
    """Callable standing in for ``redeem.ServiceXAdapter``.

    ``outcome`` controls the stubbed ``/token/refresh`` exchange: "success"
    (default) hands back ``access_token`` (a freshly minted JWT),
    "bad_refresh_token" raises AuthorizationError (redeem.py maps this to
    BadRefreshTokenError -> 400), and "unreachable" raises a network-shaped
    exception (redeem.py maps this to RedeemError -> 502). Also records the
    refresh_token it was constructed with so tests can assert it is never
    logged.
    """

    def __init__(self) -> None:
        self.outcome: str = "success"
        self.access_token: str = _make_servicex_access_token()
        self.received_refresh_token: str | None = None

    def __call__(self, url: str, *, refresh_token: str) -> _FakeServiceXAdapter:
        self.received_refresh_token = refresh_token
        return _FakeServiceXAdapter(self)


@pytest.fixture
def stub_servicex_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> ServiceXBackendStub:
    stub = ServiceXBackendStub()
    monkeypatch.setattr("servicex_token_service.redeem.ServiceXAdapter", stub)
    return stub


@pytest.fixture
def make_client(
    stub_jwks_fetch: JwksFetchStub,
) -> Callable[[Settings], httpx.AsyncClient]:
    """Factory building an ASGI test client around a fresh app for *settings*."""

    def _make(settings: Settings) -> httpx.AsyncClient:
        app = create_app(settings)
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        )

    return _make


@pytest.fixture
async def client(
    make_client: Callable[[Settings], httpx.AsyncClient], settings: Settings
) -> AsyncIterator[httpx.AsyncClient]:
    async with make_client(settings) as test_client:
        yield test_client
