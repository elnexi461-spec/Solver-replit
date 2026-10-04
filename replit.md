# Solver-replit

Private, authenticated HTTP API and console for the vendored CAPTCHA solver.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — build and run the API server
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- Required secret: `CAPTCHA_API_KEY` — Bearer token required by `POST /api/solve`; configure it in Replit Secrets, never in source or the console.
- The Python bridge uses the locked dependencies in `pyproject.toml`/`uv.lock` and Python 3.11. Browser runtime libraries are listed in `.replit`.
- `GET /api/healthz` is a liveness check; `GET /api/health` checks the browser runtime; `GET /api/service-info` describes the API.

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- Solver: Python 3.11 bridge to the vendored upstream dispatcher and CloakBrowser
- Validation: Zod (`zod/v4`) and the upstream Pydantic request model
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (ESM bundle) and Vite

## Where things live

- `artifacts/api-server/src/routes/solver.ts` — authenticated HTTP endpoints and bridge lifecycle
- `artifacts/api-server/src/solver_bridge.py` — loads and calls the original Python dispatcher
- `artifacts/api-server/vendor/captcha-solver-global/` — vendored upstream solver implementation
- `artifacts/solver-console/src/` — status and API information console
- `lib/api-spec/openapi.yaml` — API contract source of truth

## Architecture decisions

- All public API routes are under `/api`; the router is mounted at that prefix to match the Replit service path.
- `POST /api/solve` requires a timing-safe Bearer token comparison against the server-only `CAPTCHA_API_KEY`.
- Solver work is serialized to one browser session; bridge processes are bounded and cleaned up on timeout.
- User-supplied target URLs are validated by the upstream dispatcher before navigation.

## Product

The console reports transport and solver-runtime health. Authorized callers can submit supported CAPTCHA solver requests to the upstream dispatcher.

## User preferences

Keep the existing repository and upstream solver integration; do not replace it with a mock or put the API key in client code.

## Gotchas

- A healthy `/api/healthz` response only confirms the HTTP process is alive; use `/api/health` to check browser launch.
- The API returns `503` from `/api/solve` when `CAPTCHA_API_KEY` is not configured.
- After editing the OpenAPI contract, run the API-spec codegen command before typechecking.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
