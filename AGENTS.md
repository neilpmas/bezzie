# Bezzie — Agent Guide

## Commands

```sh
npm run build    # TypeScript compile
npm test         # run all tests (Vitest, real Workers environment)
npm run lint     # ESLint
```

Always run `npm run build && npm test && npm run lint` after every change. All three must pass before the task is done.

## Key files

| File | Purpose |
|---|---|
| `src/index.ts` | Public API — `createBezzie()`, exports |
| `src/routes.ts` | `/login`, `/callback`, `/logout` routes |
| `src/middleware.ts` | JWT validation, token refresh, context |
| `src/discovery.ts` | OIDC discovery cache (per-instance) |
| `src/adapters/` | `SessionAdapter` interface + implementations |
| `test/` | Tests mirror `src/` — one file per source file |

## Conventions

- TypeScript strict mode — no `any`, zero lint warnings
- Tests use `MemoryAdapter` — never use real KV in tests
- Do not commit or push — Neil does that

## Architecture

Bezzie is a BFF OAuth 2.0 library for Cloudflare Workers. It owns the OAuth flow and issues an HttpOnly session cookie to the browser — JWTs never touch the browser. Sessions are stored in Cloudflare KV (or a pluggable adapter).
