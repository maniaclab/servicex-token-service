from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings

# pydantic-settings matches env vars to field names case-insensitively, so the
# uppercase env var names (BROKER_JWKS_URL, ...) map to these fields without
# explicit aliases.


class Settings(BaseSettings):
    # Route handlers receive Settings via ``Depends``. FastAPI builds a request
    # model from the callable's signature, and the pydantic-settings
    # ``BaseSettings.__init__`` exposes private (``_cli_parse_args`` ...)
    # parameters that FastAPI cannot turn into fields. Overriding ``__init__``
    # with a plain ``**data`` signature keeps env loading intact while giving
    # FastAPI a clean signature to introspect.
    def __init__(self, **data: Any) -> None:
        super().__init__(**data)

    # Where the broker publishes the JWKS for its AF Broker Identity Token
    # signing keys (maniaclab/af-mcp-platform#162). The default points at a
    # broker running locally; production deployments must set BROKER_JWKS_URL
    # explicitly (see the Helm chart).
    broker_jwks_url: str = "http://localhost:8080/.well-known/jwks.json"

    # Required `iss` claim on inbound AF Broker Identity Tokens.
    broker_issuer: str = "https://mcp.af.uchicago.edu"

    # Required `aud` claim — this service's own identity in the protocol.
    expected_audience: str = "servicex-token-service"

    # The ServiceX deployment this service redeems tokens against. Fixed by
    # config, never accepted from the request body — accepting it from the
    # caller would be the same SSRF class of bug that servicex-mcp's CIMD
    # module guards against (a server-side fetch of an attacker-controlled
    # URL). One deployment of this chart serves exactly one ServiceX
    # backend; multiple backends mean multiple deployments. The default is a
    # non-resolvable placeholder (example.org, RFC 2606) — real deployments
    # always set this explicitly via Helm's config.servicexBackendUrl.
    servicex_backend_url: str = "https://servicex.example.org"

    # Wall-clock bound on the outbound POST {servicex_backend_url}/token/refresh
    # call. A ServiceX backend that never responds must not hang the request
    # forever; a timeout is treated as an infra failure (502), not a bad
    # refresh token.
    redeem_timeout_seconds: float = Field(default=10.0, gt=0)

    # Per-subject sliding-window rate limit on /v1/redeem. There is no
    # external account-lockout counter a bad refresh token could trip (unlike
    # krb5-token-service's CERN AD risk) — this exists purely to bound abuse
    # of this service's own endpoint, matching condor-token-service's model.
    rate_limit_max_events: int = 30
    rate_limit_window_seconds: float = 300.0

    # How long a fetched JWKS is served from the in-process cache before a
    # refresh is attempted. A failed refresh serves the stale entry instead of
    # taking token verification down with it (see identity.py).
    jwks_cache_ttl_seconds: int = 300

    log_level: str = "INFO"

    model_config = {"env_file": ".env", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    """Return a process-wide cached Settings instance.

    Use as a FastAPI dependency (``Depends(get_settings)``) so ``.env`` is read
    once at first access rather than re-instantiated on every request.
    """
    return Settings()
