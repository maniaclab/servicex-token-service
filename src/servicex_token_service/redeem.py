"""ServiceX refresh-token redemption via ServiceXAdapter.

The user's ServiceX personal refresh token is the only secret this service
receives that it does not itself own. It is used exactly once, in-memory,
to construct a throwaway ServiceXAdapter and immediately exchanged via
ServiceX's own /token/refresh endpoint — never logged, never persisted (see
logging.TokenRedactProcessor for the backstop).

Unlike the sibling services (voms-token-service, krb5-token-service,
condor-token-service), there is no local CLI/subprocess here: the exchange
is a single HTTPS call the `servicex` package's ServiceXAdapter already
knows how to make. servicex-mcp's ServiceXBridgeProvider.submit_token uses
this exact same internal call, for the same reason (there is no public
"just validate this token" API on ServiceXAdapter).
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

import jwt
import structlog
from servicex.servicex_adapter import AuthorizationError, ServiceXAdapter

if TYPE_CHECKING:
    from servicex_token_service.config import Settings

logger = structlog.get_logger(__name__)

_DEFAULT_EXPIRES_IN = 3600  # fallback when the access token has no exp claim


class RedeemError(Exception):
    """Raised when redemption fails for a reason other than a bad refresh token.

    The message is deliberately generic where it might otherwise echo
    backend error text — logged server-side only, never returned verbatim
    to the client (see app.py).
    """


class BadRefreshTokenError(Exception):
    """Raised when ServiceX rejects the refresh token itself (its own AuthorizationError)."""


@dataclass(frozen=True)
class RedeemedToken:
    access_token: str
    expires_in: int


def _expires_in(access_token: str) -> int:
    """Return seconds until the access token's exp claim, or a default if absent.

    No signature verification — this service never validates the ServiceX
    access token's authenticity itself (ServiceX minted it and is the only
    party that needs to validate it later); this only reads a public claim
    to compute a Retry-friendly expiry hint for the caller.
    """
    try:
        payload = jwt.decode(access_token, options={"verify_signature": False})
    except jwt.InvalidTokenError:
        return _DEFAULT_EXPIRES_IN
    exp = payload.get("exp")
    if exp is None:
        return _DEFAULT_EXPIRES_IN
    remaining = int(exp) - int(time.time())
    return max(remaining, 0) or _DEFAULT_EXPIRES_IN


async def redeem(refresh_token: str, settings: Settings) -> RedeemedToken:
    """Exchange *refresh_token* for a short-lived ServiceX access token.

    Raises BadRefreshTokenError if ServiceX itself rejects the token
    (AuthorizationError), or RedeemError for any other failure (network,
    timeout, unexpected response) — the caller (app.py) maps these to 400
    and 502 respectively, matching the sibling services' error-classification
    discipline.
    """
    # ServiceXAdapter._get_authorization reads BEARER_TOKEN_FILE, but with
    # force_reauth=True (always, below) it unconditionally calls _get_token()
    # afterward, which overwrites any bearer-token-file value with the real
    # refresh-token exchange — so this isn't an active bypass in the installed
    # servicex version's force_reauth=True path. Still fail closed rather than
    # depend on that being true across every future servicex release: an
    # adapter change that skips _get_token() when the file is present would
    # silently defeat this service's whole purpose otherwise.
    if os.environ.get("BEARER_TOKEN_FILE"):
        raise RedeemError("BEARER_TOKEN_FILE must not be set for this service")

    adapter = ServiceXAdapter(
        settings.servicex_backend_url, refresh_token=refresh_token
    )
    try:
        # ServiceXAdapter has no public "just validate this token" method;
        # _get_authorization(force_reauth=True) is the smallest real call that
        # actually exercises the /token/refresh exchange (see module docstring).
        await asyncio.wait_for(
            adapter._get_authorization(force_reauth=True),
            timeout=settings.redeem_timeout_seconds,
        )
    except AuthorizationError as exc:
        raise BadRefreshTokenError(str(exc)) from exc
    except TimeoutError as exc:
        # Deliberately logger.error, same rationale as the broad except below.
        logger.error("redeem_failed", error="timed out")  # noqa: TRY400
        raise RedeemError("ServiceX backend request timed out") from exc
    except Exception as exc:
        # Deliberately logger.error (not .exception): exc_info would attach a
        # traceback whose locals include refresh_token, bypassing
        # TokenRedactProcessor entirely (it only redacts event-dict keys).
        logger.error("redeem_failed", error=str(exc))  # noqa: TRY400
        raise RedeemError("ServiceX backend request failed") from exc

    access_token = adapter.token
    if not access_token:
        raise RedeemError("ServiceX backend returned no access token")
    return RedeemedToken(
        access_token=access_token, expires_in=_expires_in(access_token)
    )
