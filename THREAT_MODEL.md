# Threat Model — bezzie

bezzie is a BFF (Backend for Frontend) OAuth 2.0 / OIDC library for Cloudflare Workers. This document describes the security model: what attacks bezzie protects against, what it explicitly does not protect against, and what the deploying application is responsible for.

---

## Architecture

```
Browser ──(session cookie)──▶ Worker (bezzie) ──(Bearer token)──▶ Upstream API
                                      │
                              Cloudflare KV
                           (sessions, PKCE state)
                                      │
                                   Auth0 / IdP
                          (JWKS, token exchange, logout)
```

The core invariant: **access tokens and refresh tokens never leave the Worker**. The browser receives only a `__Host-session` cookie. The Worker holds the tokens in KV.

---

## Attacks bezzie protects against

### Login-CSRF (state fixation)
**Attack:** An attacker initiates a login flow, captures the `?code=&state=` callback URL, and tricks the victim into completing it — logging the victim into the attacker's account.

**Mitigation:** At `/auth/login`, a short-lived `__Host-pkce-csrf` cookie is set containing a random token. At `/auth/callback`, bezzie verifies the cookie value matches the `csrfToken` stored alongside the PKCE state in KV. A cross-origin attacker cannot read or set `__Host-` cookies.

### PKCE downgrade / code injection
**Attack:** An attacker intercepts the authorization code and attempts to exchange it without the PKCE verifier.

**Mitigation:** bezzie uses `oauth4webapi` with Authorization Code + PKCE (`S256`). The code verifier is stored in KV and never sent to the browser. `oauth4webapi` verifies the code challenge at token exchange.

### Token replay (nonce)
**Attack:** An attacker replays a captured ID token from a previous login.

**Mitigation:** bezzie generates a random nonce at `/auth/login`, stores it in KV, and passes it to the authorization URL. At `/auth/callback`, `oauth4webapi` verifies the `nonce` claim in the returned ID token matches.

### Open redirect via `returnTo`
**Attack:** `?returnTo=https://evil.com` causes a post-login redirect to an attacker-controlled URL.

**Mitigation:** `returnTo` must be a same-origin, path-absolute reference: it has to start with `/`, not `//`, contain no backslashes or control characters (browsers read `/\evil.com` and `/<TAB>/evil.com` as `//evil.com`), stay under 2 KB, and resolve to the same origin when parsed. It is checked when stored at `/login` and again before redirecting at `/callback`. Anything else falls back to `defaultReturnTo`.

### Session fixation
**Attack:** An attacker pre-plants a session cookie, causes the victim to log in, and then reuses the pre-planted session ID.

**Mitigation:** At `/auth/callback`, bezzie explicitly deletes any pre-existing session cookie value from KV before creating the new authenticated session.

### JWT theft via XSS
**Attack:** XSS on the frontend reads tokens from `localStorage` or JavaScript-accessible cookies.

**Mitigation:** Tokens are never sent to the browser. The `__Host-session` cookie is `HttpOnly` — JavaScript cannot read it. Even a full XSS compromise can only make authenticated requests during the session, not exfiltrate the tokens themselves.

### Token refresh race condition (double-refresh)
**Attack / failure:** Two concurrent requests both find an expired session and attempt to refresh simultaneously, so one refresh token is redeemed twice. With rotating refresh tokens, many IdPs treat the second redemption as theft and can revoke the whole token family, ending the session.

**Mitigation (best-effort, no lock):** bezzie does **not** hold a lock around refreshes. Instead, when a refresh fails with `invalid_grant`, it re-reads the session (immediately, then once more after 250 ms) looking for one that a concurrent request has already refreshed, and uses that if found. It deletes the session only if none appears. This recovers the common case but cannot guarantee anything: the IdP may already have revoked the family, and on eventually consistent stores such as Cloudflare KV the winner's write can take up to a minute to become visible elsewhere. See "Refresh token rotation race" below, and configure your IdP's refresh-token reuse/overlap interval (e.g. Auth0's rotation "leeway") to absorb bursts of parallel requests. If you need a strict guarantee, serialise refreshes per session in a single-writer store (e.g. a Durable Object) and use it as the adapter.

**Refresh failures that aren't `invalid_grant`** (timeouts, network errors, IdP 5xx, storage errors while saving the new tokens) fail only that request; the session is kept so the next request can retry. Only a definitive `invalid_grant` removes the session.

### Expired access token with no refresh token
**Failure:** A provider that issues no refresh token (for example `offline_access` was not granted) would otherwise leave the session "authenticated" with a dead access token until its KV TTL.

**Mitigation:** Once the access token has actually expired and the session has no refresh token, the session is deleted and the request is unauthenticated (401). Inside the refresh buffer, before real expiry, the token is still accepted.

### PKCE state key collisions
**Attack:** KV key collisions between session keys and PKCE state keys cause session data to be misinterpreted.

**Mitigation:** All KV keys are namespaced by type: `session:`, `pkce:`, `discovery:`.

### Slow IdP / request timeout
**Attack:** A slow or unresponsive IdP hangs Worker requests indefinitely.

**Mitigation:** All outbound fetches to the IdP (discovery, token exchange, revocation, JWKS) use `AbortSignal.timeout(5000)` — 5 second timeout.

### Auth-endpoint flood / storage quota exhaustion
**Attack:** Every unauthenticated `GET /login` writes a PKCE-state entry to the session adapter. On Cloudflare KV's free tier (1,000 writes/day), a trivial unauthenticated loop against `/login` exhausts that quota in minutes — after which `adapter.set` starts failing and nobody can log in. This denies login to real users; it does not require guessing any credential.

**Mitigation:** `/login` and `/callback` are rate-limited by client IP by default (`rateLimit` config), with an in-memory pre-filter in front of the adapter-backed counter so the counters themselves don't consume the quota they protect. IPv6 clients are limited by /64 prefix so one host can't rotate addresses within its allocation. `CF-Connecting-IP` is trusted only on Cloudflare Workers (or with `trustProxyHeaders: true`), since on other runtimes a client can send it itself; with no trustworthy IP, limiting is skipped (and a warning logged) rather than sharing one bucket. The in-memory tier is capped at 10,000 buckets so a flood of distinct keys cannot grow it without bound. Fails open on any counter-store error. See the README's Security section.

**Explicitly not covered by this:** credential-stuffing or password brute-force. With a hosted IdP, the actual password submission happens on the IdP's own login page, which bezzie never sees — rate-limiting `/login` does nothing to slow a guessing attack against it. That is the IdP's responsibility (e.g. Auth0 Attack Protection, Okta ThreatInsight).

**Also not covered by this:** a *sustained* flood operating right at the configured rate for a long period. The default (`limit: 10, windowSeconds: 120`) bounds burst throughput — it turns "exhausted in seconds" into "would take hours of sustained, easily-detectable effort" — but one determined IP sustaining the allowed rate for a full day can still exceed a typical free-tier daily write quota. This is rate limiting, not a hard daily cap; treat it as one layer, and pair it with edge-level protection (e.g. Cloudflare's own Rate Limiting rules) for an actual guarantee.

---

## What bezzie does NOT protect against

### Compromised Cloudflare KV
If an attacker gains write access to the KV namespace, they can forge sessions. KV access control is the deploying application's responsibility.

### Compromised IdP
If the IdP (e.g. Auth0) is compromised, all bets are off. bezzie trusts the IdP's JWKS and token responses. Monitor your IdP configuration for unexpected changes.

### Worker-level code injection
If the Worker itself is compromised (e.g. malicious npm package, supply chain attack), tokens in KV are accessible. Audit your dependencies.

### Network-level attacks (TLS stripping, BGP hijacking)
bezzie assumes HTTPS. The `__Host-` cookie prefix enforces `Secure` and `Path=/` — the cookie will not be sent over HTTP. Deploy only behind HTTPS.

### IdP token revocation after logout
bezzie calls the IdP's revocation endpoint for refresh tokens at logout (if `revocation_endpoint` is present in OIDC discovery). However, access tokens are typically not revocable at most IdPs (they expire on their own). Short access token lifetimes (15–60 min) limit the exposure window.

### Refresh token rotation race
There is no lock (see above), so parallel requests that find an expired token can each attempt a refresh. Not a confidentiality breach, but with an IdP that rotates refresh tokens and revokes the family on reuse, a burst of parallel requests right at token expiry can end a user's session and force a fresh login. Mitigate at the IdP with a reuse-overlap interval, and avoid firing many parallel API calls from the frontend the instant a token expires.

### Upstream API token validation
bezzie forwards access tokens to upstream APIs in `Authorization: Bearer` headers. **It is the upstream's responsibility to validate these tokens** — verify the signature against the IdP's JWKS, check `iss`, `aud`, and `exp`. bezzie does not proxy validation results. Its own `validateAccessToken` option is diagnostic only: a failed check is logged (once) and the session is still trusted, because the token came directly from the IdP's token endpoint and may legitimately be opaque.

---

## Deploying application responsibilities

| Responsibility | Notes |
|---|---|
| KV namespace access control | Restrict KV access to the Worker only |
| Client secret security | Store via `wrangler secret` — never in `wrangler.toml` |
| Upstream token validation | Validate Bearer tokens in every upstream service |
| Short access token TTL | Configure 15–60 min at the IdP |
| HTTPS only | Enforce at Cloudflare — never serve over HTTP in production |
| Dependency auditing | Run `npm audit` regularly — bezzie itself has minimal dependencies |

---

### Details worth knowing
- **Logout CSRF:** `POST /logout` has no CSRF token. It relies on the session cookie being `SameSite=Lax`, which browsers do not attach to cross-site POSTs. Do not weaken the cookie's `SameSite` attribute.
- **`id_token_hint` in the logout URL:** the ID token is passed to the IdP's logout endpoint as a query parameter (standard OIDC), so it can appear in browser history and IdP logs.
- **Tokens at rest:** access and refresh tokens are stored as plain JSON in the session adapter (see "Compromised Cloudflare KV").

---

## Out of scope

- General DDoS / bot detection at the edge — use Cloudflare's built-in rate limiting rules and bot management. Bezzie's own `/login`/`/callback` rate limiting (above) is narrower and specific: it defends bezzie's own storage write quota, not the network or application layer generally.
- Credential-stuffing / password brute-force protection — the actual credential submission happens on the IdP's own page, which bezzie never sees. Use the IdP's own protection (e.g. Auth0 Attack Protection, Okta ThreatInsight).
- Multi-tenant isolation — the deploying application is responsible for tenant boundaries
- Phishing — bezzie cannot protect against a user being directed to a fake login page
