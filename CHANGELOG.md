# Changelog

## [1.0.2](https://github.com/neilpmas/bezzie/compare/v1.0.1...v1.0.2) (2026-05-06)


### Documentation

* fix status to v1.0.1 stable, add version/license/github badges ([9873ace](https://github.com/neilpmas/bezzie/commit/9873ace8e47294149cbffd24a1417b5256ab6f29))

## [1.0.1](https://github.com/neilpmas/bezzie/compare/v1.0.0...v1.0.1) (2026-04-24)


### Bug Fixes

* use SameSite=Lax on __Host-pkce-csrf cookie ([919c964](https://github.com/neilpmas/bezzie/commit/919c96404fb90ac42bd5a534467836d8882ac476))

## [1.0.0](https://github.com/neilpmas/bezzie/compare/v0.2.2...v1.0.0) (2026-04-23)


### ⚠ BREAKING CHANGES

* BezzieConfig.adapter now takes SessionAdapterFactory instead of SessionAdapter<TUser>. Update: cloudflareKVAdapter(kv) — no change needed. new MemoryAdapter() → memoryAdapter(). new RedisAdapter(client) → redisAdapter(client).
* providerHints, cloudflareKV, and Bezzie.cache are removed.

### Features

* add `routes` config option to customize internal auth route paths ([658e3d1](https://github.com/neilpmas/bezzie/commit/658e3d16c452095508b3c0fac1743da3b8c1596c))
* add `routes` config option to customize internal auth route paths ([c0cb815](https://github.com/neilpmas/bezzie/commit/c0cb81551e1b1721990c274c3a3e06b6248627a9))
* add lifecycle hooks — onLogin, onLogout, onRefresh, onError (A6) ([f25eb66](https://github.com/neilpmas/bezzie/commit/f25eb66709efc1410528d779b1650ccbd87e792b))
* add lifecycle hooks — onLogin, onLogout, onRefresh, onError (A6) ([0d4b0af](https://github.com/neilpmas/bezzie/commit/0d4b0af5f91376cce296877165503edbd945cc50))
* add mapClaims option for runtime claim validation (C3) ([1523e25](https://github.com/neilpmas/bezzie/commit/1523e257884771826dce359527b81db27ef686eb))
* breaking API changes before v1.0.0 (A2, A3, A4, C10) ([a81d0a3](https://github.com/neilpmas/bezzie/commit/a81d0a339b11ed05f7ca2e89d96f105e7fc2514f))
* typed error classes and adapter factory inference (C11, C4) ([06f3494](https://github.com/neilpmas/bezzie/commit/06f34941db3f238828869696f463acf22d5c731e))
* Upstash docs, npm keywords, SECURITY.md, GitHub topics (A5, T1, T3, T5) ([08ec2e2](https://github.com/neilpmas/bezzie/commit/08ec2e21473e2d328a91b8622a5bb97c85acd403))


### Bug Fixes

* batch 2 review items (S8, S12, S10, S13, C6, C8, T2, C13) ([d88354d](https://github.com/neilpmas/bezzie/commit/d88354dd4300afd6b770d2e598c3fcfefec73389))
* batch 2 review items (S8, S12, S10, S13, C6, C8, T2, C13) ([34fc6d5](https://github.com/neilpmas/bezzie/commit/34fc6d576f0810d5d826f2e17d343f1b1d25d34d))
* final batch — providers typing, HTTP warning, docs (C1, T4, S6, … ([2111722](https://github.com/neilpmas/bezzie/commit/211172275a0ab8a35ced2ac9e988821808cfe47c))
* final batch — providers typing, HTTP warning, docs (C1, T4, S6, T6, S15, S2) ([febd24f](https://github.com/neilpmas/bezzie/commit/febd24f513e6d80a735881b2bf16a3ca179dc88f))
* **security:** S5 log JWT failures, S3 PKCE guard, C12 fetch timeouts, S14 session: prefix, S11 session fixation ([8e5dd14](https://github.com/neilpmas/bezzie/commit/8e5dd1443126037846fe47adae42db51e08f6834))
* **security:** S5 log JWT failures, S3 PKCE guard, C12 fetch timeouts… ([a40de3f](https://github.com/neilpmas/bezzie/commit/a40de3ffd4921d822b332f5e75f9479794f6d789))

## [0.2.2](https://github.com/neilpmas/bezzie/compare/v0.2.1...v0.2.2) (2026-04-23)


### Bug Fixes

* **security:** bind PKCE state to pre-login CSRF cookie (S4) ([b1f3ba3](https://github.com/neilpmas/bezzie/commit/b1f3ba31ff178ef750958ec0c6de8c6b7eae8427))
* **security:** bind PKCE state to pre-login CSRF cookie (S4) ([80b4aa2](https://github.com/neilpmas/bezzie/commit/80b4aa2defb91ac436ca56c188d2ade34b50f7d4))

## [0.2.1](https://github.com/neilpmas/bezzie/compare/v0.2.0...v0.2.1) (2026-04-18)


### Bug Fixes

* move publish step into release-please workflow ([6d96a0b](https://github.com/neilpmas/bezzie/commit/6d96a0bc84d0782020490fb8e373ab9ec5a8c1f5))
* move publish step into release-please workflow ([afb3d2f](https://github.com/neilpmas/bezzie/commit/afb3d2fb9479b0c4ffee6ea87212378bfca044f0))

## [0.2.0](https://github.com/neilpmas/bezzie/compare/v0.1.7...v0.2.0) (2026-04-18)


### Features

* add release script for automated versioning and GitHub release creation ([f076162](https://github.com/neilpmas/bezzie/commit/f076162118ae1d6875ac9d252add98802fd01a8b))
* add release script for automated versioning and GitHub release creation ([d26be01](https://github.com/neilpmas/bezzie/commit/d26be01f400de9f69e1158c04ed63a6136692ae9))
* automated releases with release-please ([cc4892e](https://github.com/neilpmas/bezzie/commit/cc4892e4e6b99c11d69f012cd1bd95682ac0154d))
* automated releases with release-please ([1c46575](https://github.com/neilpmas/bezzie/commit/1c4657570de3cf5ae647be02a9930337a46b79b7))

## Unreleased

### Added
- CSRF cookie validation tests for `/callback` and `SameSite=Lax` assertion for `/login`
- Subpath exports for adapters (`/cloudflare`, `/redis`, `/memory`) to support tree-shaking
- `routes` config option to allow consumers to override the default internal auth route paths
- Automated releases via `release-please`
- `optionalMiddleware()` — middleware that sets user context if a session exists but always calls next()
- `sideEffects: false` in `package.json` for better tree-shaking
- `engines` field in `package.json` to specify Node.js >= 18 as the minimum runtime

### Fixed
- Suppressed "Void function return value is used" IDE warnings in `test/routes.test.ts`
- Callback handler now uses `validateAuthResponse()` before exchanging code (required for `oauth4webapi` v3)
- OIDC discovery errors in `src/discovery.ts` are now caught and re-thrown with more descriptive messages
- The `error` query parameter in the callback route is now mapped to fixed error messages instead of being returned directly in the response body
- Session ID now uses 128-bit entropy (was 122-bit from randomUUID)

### Changed
- Updated GitHub Actions in `publish.yml` to use `v4`
- `middleware()` now falls back to the original access token if JWT validation fails (enabling opaque token support)
- `Session` and `Variables` are now generic, allowing for strongly-typed custom user data via `createBezzie<TUser>()`
- `Session` and `PKCEState` now include a `_type` discriminant field to simplify type checking and improve reliability of session identification
- `deleteCookie` now mirrors all cookie flags from the original set call
- Bumped TypeScript to 6.0.2 to align with latest language features and performance improvements.
