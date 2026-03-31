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
- Update `CHANGELOG.md` for every change — add an entry under `## Unreleased` describing what was changed and why. Use the format below.

## CHANGELOG format

```markdown
## Unreleased

### Added
- `optionalMiddleware()` — middleware that sets user context if a session exists but always calls next()

### Fixed
- Session ID now uses 128-bit entropy (was 122-bit from randomUUID)

### Changed
- `deleteCookie` now mirrors all cookie flags from the original set call
```

Entries go under `Added`, `Fixed`, or `Changed`. Keep them concise — one line each. If `CHANGELOG.md` does not exist yet, create it with an `## Unreleased` section at the top.

## Architecture

Bezzie is a BFF OAuth 2.0 library for Cloudflare Workers. It owns the OAuth flow and issues an HttpOnly session cookie to the browser — JWTs never touch the browser. Sessions are stored in Cloudflare KV (or a pluggable adapter).
