# servicex-token-service Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (or superpowers:subagent-driven-development if executing in this session).

**Goal:** Build servicex-token-service — a stateless FastAPI credential-redemption
microservice matching the `voms-token-service`/`krb5-token-service`/
`condor-token-service` pattern — that exchanges a user's ServiceX personal
refresh token (handed to it per-call by the af-mcp-broker) for a short-lived
ServiceX access token via ServiceX's own `/token/refresh`, per the design in
`docs/plans/2026-09-08-servicex-token-service-design.md`.

**Architecture:** One route (`POST /v1/redeem`) plus `GET /healthz`/`GET /readyz`.
Inbound auth is an AF Broker Identity Token (RS256, verified against the
broker's JWKS via `identity.py`, ported near-verbatim from the sibling
services — proves the call came from the broker, carries no authorization
claims). The refresh token to redeem comes from the request body, never the
identity token. `redeem.py` does the actual exchange: `ServiceXAdapter(url=
settings.servicex_backend_url, refresh_token=refresh_token)` then
`adapter._get_authorization(force_reauth=True)` — the exact same internal
call `servicex-mcp`'s `ServiceXBridgeProvider.submit_token` uses, for the
same reason (no public "just validate this token" API). Backend URL is
fixed by server config, never accepted from the request (SSRF guard). A
per-subject sliding-window rate limiter (ported from `condor-token-service`,
not `krb5-token-service` — no external lockout counter is at risk here)
bounds abuse of the endpoint.

**Tech Stack:** Python 3.12 only (matching the sibling services), FastAPI,
uvicorn, pydantic + pydantic-settings, PyJWT + cryptography (RS256 JWKS
verification), httpx (JWKS fetch), structlog (JSON audit logging), the
`servicex` PyPI package (`ServiceXAdapter`), pixi (dependency management,
`service`/`dev` environments — NOT hatch-vcs, NOT a python-version support
matrix like servicex-mcp), pytest/pytest-asyncio, ruff + mypy (default mode,
not strict) via pre-commit, Helm + NetworkPolicy, Containerfile.

**Key reference files** (read-only, for copying patterns — never import from these):
- `/Users/kratsg/krb5-token-service/` and `/Users/kratsg/voms-token-service/` —
  `identity.py` is byte-identical between them (docstring wording only
  differs) and is the direct template for this service's `identity.py`.
  `logging.py` likewise.
- `/Users/kratsg/condor-token-service/` — the direct template for
  `ratelimit.py` (its sliding-window limiter, not krb5's more complex
  password-specific one) and for `app.py`'s overall shape (a service with no
  local secret material, closest analog to this one).
- `/Users/kratsg/servicex-mcp/src/servicex_mcp/auth/bridge_provider.py`'s
  `submit_token` method — the exact pattern for calling
  `ServiceXAdapter._get_authorization(force_reauth=True)` to validate/redeem
  a refresh token, including the comment explaining why this internal method
  is used deliberately.
- `/private/tmp/svx_check/extracted/servicex/servicex_adapter.py` (or the
  installed `servicex` package path) — `ServiceXAdapter.__init__`,
  `_get_authorization`, `_get_token`, `AuthorizationError` — read these
  directly, don't assume signatures.

---

## Task 0: Project scaffolding

**Files:**
- Create: `pyproject.toml`, `pixi.toml`, `.pre-commit-config.yaml`, `.gitignore`, `README.md`, `tbump.toml`
- Create: `src/servicex_token_service/__init__.py`, `src/servicex_token_service/py.typed`
- Create: `Containerfile`

**Step 1: Write `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling>=1.26"]
build-backend = "hatchling.build"

[project]
name = "servicex-token-service"
version = "0.1.0"
description = "ServiceX refresh-token redemption for the UChicago ATLAS Analysis Facility MCP platform"
requires-python = ">=3.12,<3.13"
# Dependencies are managed by pixi — see pixi.toml at the workspace root.
dependencies = []

[tool.hatch.build.targets.wheel]
packages = ["src/servicex_token_service"]

[tool.ruff]
show-fixes = true
target-version = "py312"

[tool.ruff.lint]
extend-select = [
  "ARG", "B", "BLE", "C4", "DTZ", "EM", "EXE", "FA", "FLY", "FURB", "G",
  "I", "ICN", "ISC", "LOG", "PERF", "PGH", "PIE", "PL", "PT", "PTH",
  "PYI", "Q", "RET", "RSE", "RUF", "SIM", "SLOT", "T10", "T20", "TC",
  "TRY", "UP", "YTT",
]
ignore = [
  "PLR09", "PLR2004",
  "TRY003",  # Long exception messages inline — custom exception classes would be over-engineering
  "EM101",   # String literal in exception
  "EM102",   # f-string in exception
  "ISC001",  # Conflicts with the ruff formatter
]

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["ARG"]

[tool.ruff.lint.isort]
known-first-party = ["servicex_token_service"]

[tool.pytest.ini_options]
pythonpath = ["src", "."]
testpaths = ["tests"]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "function"
```

**Step 2: Write `pixi.toml`**

```toml
[workspace]
name = "servicex-token-service"
version = "0.1.0"
channels = ["conda-forge"]
platforms = ["linux-64", "osx-arm64", "osx-64"]
exclude-newer = "7d"

[dependencies]
python = ">=3.12,<3.13"

[feature.service.dependencies]
fastapi = ">=0.115"
uvicorn = ">=0.30"
pydantic = ">=2.7"
pydantic-settings = ">=2.3"
pyjwt = ">=2.8"
cryptography = ">=42"
httpx = ">=0.27"
structlog = ">=24.4"
servicex = ">=3.3.0"

[feature.service.pypi-dependencies]
servicex-token-service = { path = ".", editable = true }

[feature.service.tasks]
serve = { cmd = "uvicorn servicex_token_service.app:app --host 0.0.0.0 --port 8080 --reload", description = "Run dev server at http://localhost:8080" }

[feature.dev.dependencies]
pytest = ">=8.0"
pytest-asyncio = ">=0.23"
anyio = ">=4.0"
ruff = ">=0.4"
mypy = ">=1.10"
pre-commit = ">=3.7"
tbump = ">=6.7.0"

[feature.dev.tasks]
lint = { cmd = "ruff check src tests && ruff format --check src tests", description = "Ruff lint + format check" }
fmt = { cmd = "ruff format src tests && ruff check --fix src tests", description = "Format and auto-fix source" }
typecheck = { cmd = "mypy src", description = "Type-check service source" }
pre-commit = { cmd = "pre-commit run --all-files", description = "Run pre-commit hooks on all files" }
lint-all = { depends-on = ["lint", "typecheck", "pre-commit"], description = "Everything the CI lint job runs" }
test = { cmd = "pytest tests/ -v", description = "Service tests" }
check = { depends-on = ["lint", "typecheck", "test"], description = "Quick check: lint + typecheck + tests" }

[environments]
service = { features = ["service"], solve-group = "default" }
dev = { features = ["service", "dev"], solve-group = "default" }
```

**Step 3: Write `.pre-commit-config.yaml`** — copy `/Users/kratsg/condor-token-service/.pre-commit-config.yaml` verbatim (project-agnostic: trailing-whitespace, end-of-file-fixer, check-yaml, check-added-large-files, check-merge-conflict, zizmor on `.github/`; ruff/mypy deliberately run via pixi tasks, not pre-commit hooks, per that file's own comment).

**Step 4: Write `.gitignore`** — copy `/Users/kratsg/condor-token-service/.gitignore` verbatim.

**Step 5: Write `tbump.toml`** — copy `/Users/kratsg/condor-token-service/tbump.toml`, replacing the package name.

**Step 6: Write `src/servicex_token_service/__init__.py`**

```python
"""servicex-token-service: ServiceX refresh-token redemption for the AF MCP platform."""

from __future__ import annotations

__version__ = "0.1.0"
```

**Step 7: Create empty `src/servicex_token_service/py.typed`**

**Step 8: Write `Containerfile`** — adapt `/Users/kratsg/condor-token-service/Containerfile`'s multi-stage pixi pattern, but the final stage needs NO condor/htcondor apt packages, NO CLI dependency at all — just a plain Python runtime:

```dockerfile
FROM ghcr.io/prefix-dev/pixi:latest AS builder

WORKDIR /app
COPY . .

RUN pixi install --frozen --environment service

RUN echo '#!/bin/bash' > /app/entrypoint.sh && \
    pixi shell-hook --manifest-path /app/pixi.toml --environment service -s bash >> /app/entrypoint.sh && \
    echo 'exec "$@"' >> /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh

# Final stage: this service has no local CLI dependency (no kinit, no
# condor_token_create, no voms-proxy-init) — the only external call is an
# HTTPS POST to the configured ServiceX backend, made by the servicex
# package itself. A plain slim Python base is sufficient.
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/.pixi/envs/service /app/.pixi/envs/service
COPY --from=builder /app/src /app/src
COPY --from=builder /app/entrypoint.sh /app/entrypoint.sh

ENV PYTHONPATH="/app/src" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# No USER directive: uid/gid governed by the Helm chart's podSecurityContext
# (fixed non-root uid/gid, read-only rootfs, no capabilities — see values.yaml).

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "servicex_token_service.app:app", "--host", "0.0.0.0", "--port", "8080"]
```

**Step 9: Write a minimal `README.md`** summarizing the service's purpose (one paragraph, matching the design doc's opening), the `POST /v1/redeem` contract, and `pixi run -e dev serve` / `pixi run -e dev check` usage.

**Step 10: Commit**

```bash
git add pyproject.toml pixi.toml .pre-commit-config.yaml .gitignore tbump.toml README.md Containerfile src/servicex_token_service/__init__.py src/servicex_token_service/py.typed
git commit -m "chore: scaffold servicex-token-service package"
```

---

## Task 1: `config.py`

**Files:**
- Create: `src/servicex_token_service/config.py`
- Test: `tests/test_config.py`

**Step 1: Write the failing test** — port `/Users/kratsg/condor-token-service/tests/test_config.py`'s structure (env-var override tests, default-value tests, the `Settings(_env_file=None, ...)` test-construction idiom), adapted for this service's actual fields (see Step 3).

**Step 2: Run to verify it fails.**

**Step 3: Write minimal implementation**

```python
from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    def __init__(self, **data: Any) -> None:
        super().__init__(**data)

    # Where the broker publishes the JWKS for its AF Broker Identity Token
    # signing keys (maniaclab/af-mcp-platform#162).
    broker_jwks_url: str = "http://localhost:8080/.well-known/jwks.json"

    # Required `iss` claim on inbound AF Broker Identity Tokens.
    broker_issuer: str = "https://mcp.af.uchicago.edu"

    # Required `aud` claim — this service's own identity in the protocol.
    expected_audience: str = "servicex-token-service"

    # The ServiceX deployment this service redeems tokens against. Fixed by
    # config, never accepted from the request body — see the design doc's
    # SSRF rationale. One deployment of this chart serves exactly one
    # ServiceX backend; multiple backends mean multiple deployments.
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
    # refresh is attempted. A failed refresh serves the stale entry instead
    # of taking token verification down with it (see identity.py).
    jwks_cache_ttl_seconds: int = 300

    log_level: str = "INFO"

    model_config = {"env_file": ".env", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    """Return a process-wide cached Settings instance."""
    return Settings()
```

**Step 4: Run test to verify it passes.**

**Step 5: Commit**

```bash
git add src/servicex_token_service/config.py tests/test_config.py
git commit -m "feat: add Settings configuration"
```

---

## Task 2: `logging.py`

**Files:**
- Create: `src/servicex_token_service/logging.py`
- Test: `tests/test_logging.py`

Port `/Users/kratsg/condor-token-service/src/condor_token_service/logging.py` verbatim except `TokenRedactProcessor._REDACTED_KEYS`, which must additionally cover this service's own credential-shaped fields: `frozenset({"token", "bearer", "authorization", "refresh_token", "access_token"})`. Port `/Users/kratsg/condor-token-service/tests/test_logging.py` verbatim, extending its redaction-coverage test to include `refresh_token`/`access_token`.

**Step 1-5:** Standard TDD cycle (write test, confirm fail, implement, confirm pass), then commit:

```bash
git add src/servicex_token_service/logging.py tests/test_logging.py
git commit -m "feat: add structlog configuration with credential redaction"
```

---

## Task 3: `ratelimit.py`

**Files:**
- Create: `src/servicex_token_service/ratelimit.py`
- Test: `tests/test_ratelimit.py`

Port `/Users/kratsg/condor-token-service/src/condor_token_service/ratelimit.py` verbatim (it is already domain-agnostic — a generic per-key sliding-window limiter, no condor-specific logic) and its test file `/Users/kratsg/condor-token-service/tests/test_ratelimit.py` verbatim, only changing the import path.

**Step 1-5:** Standard TDD cycle, commit:

```bash
git add src/servicex_token_service/ratelimit.py tests/test_ratelimit.py
git commit -m "feat: add per-subject sliding-window rate limiter"
```

---

## Task 4: `identity.py`

**Files:**
- Create: `src/servicex_token_service/identity.py`
- Test: `tests/test_identity.py`

Port `/Users/kratsg/krb5-token-service/src/krb5_token_service/identity.py` (or voms's — they are identical) verbatim except the module docstring's second paragraph, which references what claims the *specific* mint request carries versus the token — reword to reference the redeem request's `refresh_token` field rather than krb5's username/password. Everything else (JWKS TTL cache, single-flight refresh-per-URL, stale-on-refresh-failure fallback, `verify_broker_token`, `_select_jwk`, `peek_sub`) is unchanged — this logic has zero krb5/voms-specific content.

Port `/Users/kratsg/krb5-token-service/tests/test_identity.py` (or voms's equivalent) verbatim, only changing the import path.

**Step 1-5:** Standard TDD cycle, commit:

```bash
git add src/servicex_token_service/identity.py tests/test_identity.py
git commit -m "feat: add AF Broker Identity Token verification"
```

---

## Task 5: `redeem.py` — the ServiceX-specific redemption logic

**Files:**
- Create: `src/servicex_token_service/redeem.py`
- Test: `tests/test_redeem.py`

This is the one genuinely new module — the equivalent of krb5's `minting.py`/condor's `minting.py`, but for ServiceX. Read `/Users/kratsg/servicex-mcp/src/servicex_mcp/auth/bridge_provider.py`'s `submit_token` method again before writing this (same internal-API call, same reasoning for using it).

**Step 1: Write the failing test**

```python
"""Tests for redeem.py."""

from __future__ import annotations

import time

import jwt
import pytest

from servicex_token_service.config import Settings
from servicex_token_service.redeem import BadRefreshTokenError, RedeemError, redeem


def _make_access_token(exp_in: int = 600) -> str:
    return jwt.encode(
        {"exp": int(time.time()) + exp_in, "sub": "servicex-user"},
        "irrelevant-since-unverified",
        algorithm="HS256",
    )


class TestRedeem:
    async def test_returns_access_token_and_expires_in(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(_env_file=None, servicex_backend_url="https://sx.example.com")
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

        monkeypatch.setattr("servicex_token_service.redeem.ServiceXAdapter", FakeAdapter)
        result = await redeem("the-refresh-token", settings)
        assert result.access_token == access_token
        assert 590 <= result.expires_in <= 600

    async def test_bad_refresh_token_raises_bad_refresh_token_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from servicex.servicex_adapter import AuthorizationError

        settings = Settings(_env_file=None, servicex_backend_url="https://sx.example.com")

        class FakeAdapter:
            def __init__(self, url: str, *, refresh_token: str) -> None:
                pass

            async def _get_authorization(self, *, force_reauth: bool) -> dict[str, str]:
                raise AuthorizationError("Not authorized to access serviceX at https://sx.example.com")

        monkeypatch.setattr("servicex_token_service.redeem.ServiceXAdapter", FakeAdapter)
        with pytest.raises(BadRefreshTokenError):
            await redeem("bad-token", settings)

    async def test_backend_unreachable_raises_redeem_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(_env_file=None, servicex_backend_url="https://sx.example.com")

        class FakeAdapter:
            def __init__(self, url: str, *, refresh_token: str) -> None:
                pass

            async def _get_authorization(self, *, force_reauth: bool) -> dict[str, str]:
                raise TimeoutError("connect timed out")

        monkeypatch.setattr("servicex_token_service.redeem.ServiceXAdapter", FakeAdapter)
        with pytest.raises(RedeemError):
            await redeem("some-token", settings)

    async def test_access_token_with_no_exp_claim_uses_default_expiry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(_env_file=None, servicex_backend_url="https://sx.example.com")
        access_token = jwt.encode({"sub": "servicex-user"}, "x", algorithm="HS256")

        class FakeAdapter:
            def __init__(self, url: str, *, refresh_token: str) -> None:
                self.token: str | None = None

            async def _get_authorization(self, *, force_reauth: bool) -> dict[str, str]:
                self.token = access_token
                return {}

        monkeypatch.setattr("servicex_token_service.redeem.ServiceXAdapter", FakeAdapter)
        result = await redeem("token-no-exp", settings)
        assert result.access_token == access_token
        assert result.expires_in > 0  # falls back to a sane default
```

Note: these tests patch `ServiceXAdapter` at the point of use in `redeem.py`, mirroring how `tests/auth/test_bridge_provider.py` in servicex-mcp patches it — read that file for the exact monkeypatching idiom if this doesn't quite work against the installed `mcp`-free test setup here (this repo has no `mcp` dependency at all, unlike servicex-mcp — don't import anything from `servicex_mcp` or `mcp`, this is a fully standalone service).

**Step 2: Run to verify it fails.**

**Step 3: Write minimal implementation**

```python
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
    adapter = ServiceXAdapter(settings.servicex_backend_url, refresh_token=refresh_token)
    try:
        await adapter._get_authorization(force_reauth=True)  # pylint: disable=protected-access
    except AuthorizationError as exc:
        raise BadRefreshTokenError(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.error("redeem_failed", error=str(exc))
        raise RedeemError("ServiceX backend request failed") from exc

    access_token = adapter.token
    if not access_token:
        raise RedeemError("ServiceX backend returned no access token")
    return RedeemedToken(access_token=access_token, expires_in=_expires_in(access_token))
```

**Step 4: Run test to verify it passes.**

**Step 5: Commit**

```bash
git add src/servicex_token_service/redeem.py tests/test_redeem.py
git commit -m "feat: add ServiceX refresh-token redemption"
```

---

## Task 6: `app.py` — the FastAPI application

**Files:**
- Create: `src/servicex_token_service/app.py`
- Test: `tests/conftest.py`
- Test: `tests/test_redeem_endpoint.py`
- Test: `tests/test_health.py`

**Step 1: Write `tests/conftest.py`** — port `/Users/kratsg/condor-token-service/tests/conftest.py`'s shape: `rsa_private_key`/`other_rsa_private_key` fixtures, `jwks` fixture, `settings` fixture (this service's fields), `JwksFetchStub` + `stub_jwks_fetch` (unchanged — identity.py is the same module shape), `make_token` (drop condor's `unixname`/`uid`/`gid` claims — this service's identity token carries no POSIX claims, just `sub`/`jti`/`exp`/`iat`), `make_client`/`client` fixtures (unchanged shape). Replace `fake_condor_bin`/`failing_condor_bin` with a `stub_servicex_backend` fixture that monkeypatches `servicex_token_service.redeem.ServiceXAdapter` the same way Task 5's tests did, but shared/reusable across endpoint tests.

**Step 2: Write the failing test** — port `/Users/kratsg/condor-token-service/tests/test_token_endpoint.py`'s structure for `tests/test_redeem_endpoint.py`: happy path (200, `access_token`/`expires_in` in body), audit line carries required fields, no log line ever contains the refresh token OR the returned access token, missing-Authorization-header → 401, expired identity token → 401, bad refresh token → 400 (not 401 — the identity token was valid; it's the *body's* credential that's bad), backend unreachable/timeout → 502, rate-limit exceeded → 429. Port `/Users/kratsg/condor-token-service/tests/test_health.py`'s structure for `tests/test_health.py`, adapting `readyz`'s checks (see Step 3 below — no binary to check for this service; check JWKS reachability and, optionally, nothing else, since there's no local CLI).

**Step 3: Run to verify it fails.**

**Step 4: Write minimal implementation**

```python
"""FastAPI application: the redeem endpoint plus health probes.

Authorization model: none beyond identity, by design (see
identity.py's module docstring). The refresh token to redeem comes from
the request body; this service derives no authorization from the AF Broker
Identity Token's claims.
"""

from __future__ import annotations

import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, SecretStr

from servicex_token_service.config import Settings, get_settings
from servicex_token_service.identity import get_jwks, peek_sub, verify_broker_token
from servicex_token_service.logging import configure_logging
from servicex_token_service.ratelimit import RateLimiter
from servicex_token_service.redeem import BadRefreshTokenError, RedeemError, redeem

logger = structlog.get_logger(__name__)

_bearer_scheme = HTTPBearer(auto_error=False)

router = APIRouter()


class RedeemRequest(BaseModel):
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
    logger.info("audit", subject=subject, jti=jti, outcome=outcome, request_id=request_id)


@router.post("/v1/redeem", response_model=RedeemResponse)
async def redeem_endpoint(
    request: Request,
    body: RedeemRequest,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
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
        outcome = "denied" if exc.status_code == status.HTTP_401_UNAUTHORIZED else "error"
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
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded; retry after {retry_after:.0f}s",
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
    return RedeemResponse(access_token=redeemed.access_token, expires_in=redeemed.expires_in)


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
```

**Step 5: Run test to verify it passes.**

**Step 6: Commit**

```bash
git add src/servicex_token_service/app.py tests/conftest.py tests/test_redeem_endpoint.py tests/test_health.py
git commit -m "feat: add FastAPI app with /v1/redeem and health probes"
```

---

## Task 7: `test_e2e.py`

**Files:**
- Create: `tests/test_e2e.py`

Port the shape of `/Users/kratsg/condor-token-service/tests/test_e2e.py` (read it for the exact idiom): a real-deployment-only smoke test, skipped by default (`pytestmark = pytest.mark.skipif(...)` gated on an env var), which only runs when explicitly opted into against a real deployed instance over plain `httpx` — no `ASGITransport`, no `conftest.py` stubs — asserting only externally observable response shape (200, `access_token`/`expires_in` present and well-formed). No audit-log assertion: server-side logs aren't observable from an external HTTP call. This is distinct from `tests/test_redeem_endpoint.py`'s `TestHappyPath` (which already covers the stubbed-ASGI happy path + audit logging in-process) — it exists for real-infra verification, not additional in-process coverage, and is a no-op in CI until a real ServiceX deployment exists to point at.

**Step 1-5:** Standard TDD cycle, commit:

```bash
git add tests/test_e2e.py
git commit -m "test: add end-to-end smoke test"
```

---

## Task 8: Helm chart

**Files:**
- Create: `charts/servicex-token-service/{Chart.yaml,values.yaml,.helmignore}`
- Create: `charts/servicex-token-service/templates/{_helpers.tpl,deployment.yaml,service.yaml,networkpolicy.yaml}`

Copy `/Users/kratsg/condor-token-service/charts/condor-token-service/` wholesale and adapt:

- `Chart.yaml`: rename, update `description` to match this service's purpose, keep `maintainers` (kratsg).
- `values.yaml`: drop everything Condor-specific (`nodeSelector`/`affinity`/`tolerations` comments about login nodes, `poolPassword` Secret block, `condorIdentityDomain`/`condorTrustDomain`/`tokenLifetimeSeconds`/`condorTokenCreateBin`). Keep: `replicaCount` (2, matching condor's HA rationale — this service is stateless so multiple replicas are trivially safe, unlike krb5/voms which pin to specific nodes for local secret access), `image`/`imagePullSecrets`, `config.{brokerJwksUrl,brokerIssuer,expectedAudience,rateLimitMaxEvents,rateLimitWindowSeconds,logLevel}` **plus new** `config.servicexBackendUrl` and `config.redeemTimeoutSeconds`, `podSecurityContext`/`containerSecurityContext` (unchanged — same hardening applies), `service.port`, `resources: {}`.
  `networkPolicy`: keep the `broker` ingress block unchanged (same broker-only ingress rule). The `egress.jwks` block stays for the JWKS fetch, but **add a new `egress.servicexBackend` block** (namespaceSelector/podSelector don't apply here — this is an external HTTPS endpoint, not in-cluster, so use an `ipBlock`-shaped or DNS-egress rule; if the cluster's CNI doesn't support FQDN-based egress rules, document in a comment that operators must adapt this block to their cluster's actual egress-control mechanism for the specific ServiceX backend's IP range, since this is the one genuinely new network dependency none of the three sibling services have).
- `templates/_helpers.tpl`: copy structurally, rename.
- `templates/deployment.yaml`: drop the pool-password init container and its volume entirely (no local secret to fix permissions on). Env vars: `BROKER_JWKS_URL`, `BROKER_ISSUER`, `EXPECTED_AUDIENCE`, `SERVICEX_BACKEND_URL`, `REDEEM_TIMEOUT_SECONDS`, `RATE_LIMIT_MAX_EVENTS`, `RATE_LIMIT_WINDOW_SECONDS`, `LOG_LEVEL`, sourced from `values.config.*`. Command: `uvicorn servicex_token_service.app:app --host 0.0.0.0 --port 8080`.
- `templates/service.yaml`: copy structurally, rename.
- `templates/networkpolicy.yaml`: copy structurally; add the new egress rule for `config.servicexBackendUrl`'s host per the values.yaml note above.
- Drop `poolPassword`-related anything from every template — there is no local secret in this service at all.

**Step 1: Validate**

```bash
helm lint charts/servicex-token-service
helm template servicex-token-service charts/servicex-token-service --debug > /dev/null
```

Fix anything flagged.

**Step 2: Commit**

```bash
git add charts/
git commit -m "chore: add Helm chart"
```

---

## Task 9: CI/CD

**Files:**
- Create: `.github/workflows/{ci.yaml,docker.yaml}`, `.github/dependabot.yml`

Copy `/Users/kratsg/condor-token-service/.github/` wholesale, adapting:

- `ci.yaml`: keep the `lint`/`test`/`helm-lint` jobs structurally identical (rename references). **Drop the `integration-condor` job entirely** — there is no analogous "real backend" integration test for this service to run in CI without live ServiceX credentials (mirrors servicex-mcp's own choice to leave live-credential testing out of CI, deferred to Giordon). Note in a comment that a live-ServiceX e2e test could be added later behind an env-var gate, matching the `CONDOR_MINI_INTEGRATION` pattern, once real test credentials exist.
- `docker.yaml`: copy structurally (builds and pushes the Containerfile image to `ghcr.io/maniaclab/servicex-token-service`).
- `dependabot.yml`: copy structurally.

**Step 1: Validate** — `pixi run -e dev pre-commit run --all-files` (this repo's pre-commit config includes `check-github-workflows`/zizmor equivalents only if added; if this family's `.pre-commit-config.yaml` doesn't validate workflow YAML the way servicex-mcp's does, at minimum confirm the YAML parses: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yaml'))"` for each file).

**Step 2: Commit**

```bash
git add .github/
git commit -m "chore: add CI/CD workflows"
```

---

## Task 10: Full verification pass

**Step 1:** `pixi install -e dev`

**Step 2:** `pixi run -e dev check` (lint + typecheck + test) — fix anything red.

**Step 3:** `helm lint charts/servicex-token-service && helm template servicex-token-service charts/servicex-token-service --debug > /dev/null`

**Step 4:** Review `git log --oneline` against this plan's task list — confirm nothing was skipped.

**Step 5:** Report to Giordon: what's done (the full redeem service, tested, charted, CI'd), what's explicitly deferred (servicex-mcp's broker-mode client factory, the af-credentials ServiceX-redeem client, wiring into a live af-mcp-platform broker, live-ServiceX CI), and ask whether to push/open a PR or keep building on this branch.
