"""FastAPI application: the redeem endpoint plus health probes.

Authorization model: none beyond identity, by design (see
identity.py's module docstring). The refresh token to redeem comes from
the request body; this service derives no authorization from the AF Broker
Identity Token's claims.
"""

from __future__ import annotations

import math
import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, SecretStr

from servicex_token_service.config import Settings, get_settings
from servicex_token_service.identity import get_jwks, peek_sub, verify_broker_token
from servicex_token_service.logging import configure_logging
from servicex_token_service.ratelimit import RateLimiter
from servicex_token_service.redeem import BadRefreshTokenError, RedeemError, redeem

logger = structlog.get_logger(__name__)

# ``auto_error=False`` so a missing header is audited before the 401 is raised.
_bearer_scheme = HTTPBearer(auto_error=False)

router = APIRouter()


class RedeemRequest(BaseModel):
    # extra="forbid": the backend URL is fixed by server config, never by
    # the request (SSRF guard, see the design doc) — reject any attempt to
    # send one (or any other unexpected field) with a clear 422 instead of
    # silently ignoring it.
    model_config = ConfigDict(extra="forbid")

    refresh_token: SecretStr


class RedeemResponse(BaseModel):
    access_token: str
    expires_in: int


def _audit(
    *,
    subject: str | None,
    jti: str | None,
    outcome: str,  # "issued" | "denied" | "error"
    request_id: str,
) -> None:
    """One structlog JSON audit line per request.

    NEVER include the refresh token or the minted access token here — only
    subject/jti/outcome. See also logging.TokenRedactProcessor for the
    backstop.
    """
    logger.info(
        "audit", subject=subject, jti=jti, outcome=outcome, request_id=request_id
    )


@router.post("/v1/redeem", response_model=RedeemResponse)
async def redeem_endpoint(
    request: Request,
    body: RedeemRequest,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)
    ],
) -> RedeemResponse:
    settings: Settings = request.app.state.settings
    rate_limiter: RateLimiter = request.app.state.rate_limiter
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())

    if credentials is None:
        _audit(subject=None, jti=None, outcome="denied", request_id=request_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        claims = await verify_broker_token(credentials.credentials, settings)
    except HTTPException as exc:
        # 401 (invalid token) is a denial; anything else (e.g. the JWKS
        # fetch's 502) is a platform error, not the caller's fault.
        outcome = (
            "denied" if exc.status_code == status.HTTP_401_UNAUTHORIZED else "error"
        )
        _audit(
            subject=peek_sub(credentials.credentials),
            jti=None,
            outcome=outcome,
            request_id=request_id,
        )
        raise

    subject: str = claims["sub"]
    jti: str | None = claims.get("jti")

    retry_after = rate_limiter.try_acquire(subject)
    if retry_after is not None:
        _audit(subject=subject, jti=jti, outcome="denied", request_id=request_id)
        retry_after_seconds = max(1, math.ceil(retry_after))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded; retry after {retry_after_seconds}s",
            headers={"Retry-After": str(retry_after_seconds)},
        )

    try:
        redeemed = await redeem(body.refresh_token.get_secret_value(), settings)
    except BadRefreshTokenError:
        _audit(subject=subject, jti=jti, outcome="denied", request_id=request_id)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired refresh token",
        ) from None
    except RedeemError as exc:
        _audit(subject=subject, jti=jti, outcome="error", request_id=request_id)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="ServiceX token redemption failed",
        ) from exc

    _audit(subject=subject, jti=jti, outcome="issued", request_id=request_id)
    return RedeemResponse(
        access_token=redeemed.access_token, expires_in=redeemed.expires_in
    )


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request) -> dict[str, str]:
    """Ready only when the broker JWKS is fetchable.

    Deliberately does NOT check ServiceX backend reachability — a ServiceX
    outage must not flap this pod's readiness (mirrors krb5-token-service's
    readyz deliberately not checking KDC reachability).
    """
    settings: Settings = request.app.state.settings
    try:
        await get_jwks(settings)
    except HTTPException as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"broker JWKS endpoint unreachable: {settings.broker_jwks_url}",
        ) from exc
    return {"status": "ready"}


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application; tests pass explicit Settings, production uses env."""
    if settings is None:
        settings = get_settings()
    configure_logging(settings.log_level)
    application = FastAPI(
        title="servicex-token-service",
        description="ServiceX refresh-token redemption for the AF MCP platform",
        version="0.1.0",
    )
    application.state.settings = settings
    application.state.rate_limiter = RateLimiter(
        max_events=settings.rate_limit_max_events,
        window_seconds=settings.rate_limit_window_seconds,
    )
    application.include_router(router)
    return application


app = create_app()
