"""End-to-end test against a real deployment — never faked.

Requires a real deployed servicex-token-service (with real connectivity to
a real ServiceX backend), a real af-mcp-broker minting AF Broker Identity
Tokens, and a real ServiceX personal refresh token for a real ServiceX
user. None of that can be faked without defeating the point of an e2e
test, so this module is skipped unless explicitly opted into:

    SERVICEX_E2E=1 \\
    SERVICEX_TOKEN_SERVICE_URL=https://servicex-token.af.uchicago.edu \\
    AF_BROKER_IDENTITY_TOKEN=<freshly-minted broker token> \\
    SERVICEX_E2E_REFRESH_TOKEN=<real ServiceX personal refresh token> \\
    pixi run test

The broker token must be freshly minted (they are short-lived) with
aud=servicex-token-service.
"""

from __future__ import annotations

import os

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("SERVICEX_E2E") != "1",
    reason="requires a real deployment, broker, and ServiceX refresh token; set SERVICEX_E2E=1 to run",
)


async def test_redeem_refresh_token_against_real_service() -> None:
    base_url = os.environ["SERVICEX_TOKEN_SERVICE_URL"]
    broker_token = os.environ["AF_BROKER_IDENTITY_TOKEN"]
    refresh_token = os.environ["SERVICEX_E2E_REFRESH_TOKEN"]

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{base_url}/v1/redeem",
            headers={"Authorization": f"Bearer {broker_token}"},
            json={"refresh_token": refresh_token},
            timeout=30.0,
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    # A real ServiceX access token is a JWT; sanity-check shape without decoding it.
    assert body["access_token"].count(".") == 2
    assert body["expires_in"] > 0
