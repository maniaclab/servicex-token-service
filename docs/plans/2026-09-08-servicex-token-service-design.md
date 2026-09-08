# servicex-token-service design

Status: approved.

## Purpose

A stateless credential-redemption microservice for the UChicago ATLAS
Analysis Facility MCP platform (`maniaclab/af-mcp-platform`), matching the
existing custodian pattern used by `voms-token-service`, `krb5-token-service`,
and `condor-token-service`. It exists so that `servicex-mcp`'s future
broker-mode support (deferred — see servicex-mcp's own design doc) has
something to redeem against: the broker holds a user's long-lived ServiceX
personal refresh token (vaulted the same way it already vaults CERN
passwords/passphrases for the sibling services) and hands it to this
service, per call, to exchange for a short-lived ServiceX access token.

Explicitly out of scope for this build (confirmed with Giordon): wiring
servicex-mcp's own broker-mode client factory, and extending the shared
`af-credentials` library with a ServiceX-redeem client class. Those are a
separate, larger, cross-repo change. This repo is the custodian service
only — the thing the broker calls, not the thing servicex-mcp calls.

## Why this is architecturally simpler than its siblings

`voms-token-service`/`krb5-token-service`/`condor-token-service` all shell
out to a local CLI (`voms-proxy-init`, `kinit`, `condor_token_create`) that
itself talks to a backend (CA/VOMS, KDC, Condor collector) over a
protocol none of those services implement themselves — the Python app's
job is subprocess plumbing, stdin secret-passing, and stderr
classification.

ServiceX has no such CLI. The "secret" here is a personal refresh token,
and "minting" is a single HTTPS `POST {backend_url}/token/refresh` call —
exactly what `servicex.servicex_adapter.ServiceXAdapter._get_authorization`
already does (servicex-mcp's `ServiceXBridgeProvider.submit_token` calls
this same method for the same reason: there is no public
"just validate this token" API). So this service:

- has no subprocess, no local secret material, no CLI dependency, no
  Containerfile complexity beyond a plain Python base image;
- depends on the `servicex` PyPI package the same way servicex-mcp does;
- has exactly one credential-shaped input (the refresh token) and one
  external network dependency (the ServiceX backend), not counting the
  broker's JWKS.

## Backend URL is fixed by config, not by request

The redeem endpoint must **not** accept a `backend_url` (or dataset/query
string, or anything else attacker-influenceable) in the request body —
only the refresh token. The backend URL is one fixed, operator-configured
value per deployment (`SERVICEX_BACKEND_URL`), matching how
`condor-token-service` fixes its pool/trust domain via config rather than
per-request. Accepting an arbitrary backend URL per-request would be the
same SSRF class of bug that `servicex-mcp`'s CIMD module guards against
(a server-side fetch of an attacker-controlled URL) — here there's no
legitimate reason for the caller to choose the URL at all, since one
deployment of this service serves exactly one ServiceX instance. Serving
multiple ServiceX backends means deploying multiple instances of this
chart with different `config.servicexBackendUrl` values, exactly as you
would deploy multiple `servicex-mcp` instances for different backends.

## Architecture

```
af-mcp-broker (holds vaulted refresh tokens, mints AF Broker Identity Tokens)
        │
        │ POST /v1/redeem
        │ Authorization: Bearer <AF Broker Identity Token, aud=servicex-token-service>
        │ Body: {"refresh_token": "<user's ServiceX PAT>"}
        ▼
servicex-token-service
        │
        │ POST {SERVICEX_BACKEND_URL}/token/refresh
        │ Authorization: Bearer <refresh_token>
        ▼
ServiceX backend
```

Response: `{"access_token": "...", "expires_in": <seconds>}`. The refresh
token is used once, in-memory, for that one call, and is never logged,
persisted, or echoed back.

## Identity/auth model

Identical to the three siblings: the inbound Bearer is an AF Broker
Identity Token (RS256, verified against the broker's JWKS —
`iss`/`aud`/`exp`/`iat`/`sub`/`jti`). It proves *the call came from the
broker*; it carries no authorization claims and this service derives none
from it. The ServiceX refresh token to redeem comes from the request body,
never from the token. `identity.py` is ported near-verbatim from
`krb5-token-service`/`voms-token-service` (they are byte-identical except
docstring wording) — this is deliberately not re-derived, since it's
already a proven, reviewed implementation (JWKS TTL cache, single-flight
refresh, stale-serves-on-refresh-failure, per-`kid` key selection).

## Rate limiting

`condor-token-service`'s rate limiter is the right model to follow (not
`krb5-token-service`'s): a plain per-subject sliding-window limiter with no
distinction between "bad credential" and "infra failure" outcomes, because
— like Condor's IDTOKEN minting — there is no external account-lockout
counter a wrong refresh token could trip. It exists purely to bound abuse
of this service's own endpoint, not to protect a third party's lockout
policy. `voms-token-service` has no rate limiter at all because a bad
Globus passphrase fails a purely local `openssl` decrypt with zero
external consequence; that reasoning doesn't transfer here since redeeming
genuinely calls out to the ServiceX backend on every attempt, so some
limiter is warranted.

## Package/tooling conventions

This repo follows the `condor-token-service`/`voms-token-service`/
`krb5-token-service` house style, **not** `servicex-mcp`'s — a
deliberately different, lighter convention for this family of small FastAPI
microservices: pixi-managed dependencies (empty `project.dependencies`),
hatchling with a fixed version string (no hatch-vcs), `requires-python
">=3.12,<3.13"` only (matching the deployment target, not a support
matrix), a lighter ruff ruleset with no strict mypy mode, `service`
+ `dev` pixi environments, `Containerfile` (not `Dockerfile`), Helm chart
with a `NetworkPolicy` restricting ingress to the broker's pods/namespace
only and egress to DNS + the broker's JWKS + (new, since no sibling has
this) the ServiceX backend.

## Package layout

```
src/servicex_token_service/
├── __init__.py
├── app.py          # FastAPI app: POST /v1/redeem, GET /healthz, GET /readyz
├── config.py        # pydantic-settings: broker_jwks_url, broker_issuer,
│                     # expected_audience, servicex_backend_url,
│                     # redeem_timeout_seconds, rate_limit_*, jwks_cache_ttl_seconds
├── identity.py       # AF Broker Identity Token verification (ported near-verbatim)
├── logging.py        # structlog configuration (ported near-verbatim)
├── ratelimit.py       # per-subject sliding-window limiter (ported from condor, condor's shape not krb5's)
├── redeem.py          # the ServiceX-specific "minting" module (new)
└── py.typed
tests/
├── conftest.py
├── test_config.py
├── test_identity.py
├── test_logging.py
├── test_ratelimit.py
├── test_redeem.py
├── test_redeem_endpoint.py
├── test_health.py
└── test_e2e.py
charts/servicex-token-service/   # Chart.yaml, values.yaml, templates/{deployment,service,networkpolicy,_helpers.tpl}
.github/workflows/{ci.yaml,docker.yaml}, .github/dependabot.yml
Containerfile
pyproject.toml, pixi.toml, .pre-commit-config.yaml, tbump.toml
```

## Deferred (explicitly out of scope for this build)

- servicex-mcp's own broker-mode client factory (`BrokerServiceXClientFactory`,
  `--broker-url` CLI flag) — a separate change to the `servicex-mcp` repo.
- A ServiceX-redeem client class in the shared `af-credentials` library
  (the `ProxyClient` equivalent) — a separate, cross-repo change affecting
  `rucio-mcp`/`ami-mcp`'s shared dependency too.
- Actually wiring this service into a running `af-mcp-platform` broker
  deployment (out of this repo's control).
