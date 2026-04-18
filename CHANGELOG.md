# Changelog

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
- Automated releases via `release-please`
- `optionalMiddleware()` — middleware that sets user context if a session exists but always calls next()
- `sideEffects: false` in `package.json` for better tree-shaking
- `engines` field in `package.json` to specify Node.js >= 18 as the minimum runtime

### Fixed
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
