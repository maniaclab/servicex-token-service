"""Integration tests for GET /healthz and GET /readyz."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

    from tests.conftest import JwksFetchStub


class TestHealthz:
    async def test_healthz_is_200_unconditionally(
        self, client: httpx.AsyncClient
    ) -> None:
        resp = await client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


class TestReadyz:
    async def test_ready_when_jwks_fetchable(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/readyz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ready"}

    async def test_503_when_jwks_unreachable(
        self, client: httpx.AsyncClient, stub_jwks_fetch: JwksFetchStub
    ) -> None:
        stub_jwks_fetch.fail = True
        resp = await client.get("/readyz")
        assert resp.status_code == 503
        assert "JWKS" in resp.json()["detail"]
