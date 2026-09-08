# servicex-token-service

A stateless credential-redemption microservice for the UChicago ATLAS
Analysis Facility MCP platform (`maniaclab/af-mcp-platform`), matching the
existing custodian pattern used by `voms-token-service`,
`krb5-token-service`, and `condor-token-service`. It exists so that
`servicex-mcp`'s future broker-mode support has something to redeem
against: the broker holds a user's long-lived ServiceX personal refresh
token and hands it to this service, per call, to exchange for a
short-lived ServiceX access token.

## API

| Endpoint | Auth | Behavior |
| --- | --- | --- |
| `POST /v1/redeem` | `Authorization: Bearer <AF Broker Identity Token>` | Body `{"refresh_token": "<user's ServiceX PAT>"}`. Exchanges the refresh token for a ServiceX access token via `POST {SERVICEX_BACKEND_URL}/token/refresh`. Returns `{"access_token", "expires_in"}`. |
| `GET /healthz` | none | Liveness probe. |
| `GET /readyz` | none | Readiness probe. |

See `docs/plans/2026-09-08-servicex-token-service-design.md` for the full
design, including why the backend URL is fixed by server config and never
accepted from the request.

## Local development

Everything runs through [pixi](https://pixi.sh); dependencies live in
`pixi.toml` (this package's `pyproject.toml` intentionally declares no
dependencies).

```bash
pixi run -e dev serve   # dev server with reload -> http://localhost:8080/docs
pixi run -e dev check   # lint + typecheck + tests
```
