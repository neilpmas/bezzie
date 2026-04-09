## Unreleased

### Fixed
- The `error` query parameter in the callback route is now mapped to fixed error messages instead of being returned directly in the response body
- Session ID now uses 128-bit entropy (was 122-bit from randomUUID)

### Changed
- Bumped TypeScript to 6.0.2 to align with latest language features and performance improvements.
