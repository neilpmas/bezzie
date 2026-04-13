## Unreleased

### Added
- `optionalMiddleware()` — middleware that sets user context if a session exists but always calls next()
- `sideEffects: false` in `package.json` for better tree-shaking
- `engines` field in `package.json` to specify Node.js >= 18 as the minimum runtime

### Fixed
- Callback handler now uses `validateAuthResponse()` before exchanging code (required for `oauth4webapi` v3)
- OIDC discovery errors in `src/discovery.ts` are now caught and re-thrown with more descriptive messages
- The `error` query parameter in the callback route is now mapped to fixed error messages instead of being returned directly in the response body
- Session ID now uses 128-bit entropy (was 122-bit from randomUUID)

### Changed
- `middleware()` now falls back to the original access token if JWT validation fails (enabling opaque token support)
- `Session` and `Variables` are now generic, allowing for strongly-typed custom user data via `createBezzie<TUser>()`
- `Session` and `PKCEState` now include a `_type` discriminant field to simplify type checking and improve reliability of session identification
- `deleteCookie` now mirrors all cookie flags from the original set call
- Bumped TypeScript to 6.0.2 to align with latest language features and performance improvements.
