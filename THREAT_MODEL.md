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

**Mitigation:** `returnTo` is validated to be a relative path (starts with `/`, not `//`). Absolute URLs are rejected.

### Session fixation
**Attack:** An attacker pre-plants a session cookie, causes the victim to log in, and then reuses the pre-planted session ID.

**Mitigation:** At `/auth/callback`, bezzie explicitly deletes any pre-existing session cookie value from KV before creating the new authenticated session.

### JWT theft via XSS
**Attack:** XSS on the frontend reads tokens from `localStorage` or JavaScript-accessible cookies.

**Mitigation:** Tokens are never sent to the browser. The `__Host-session` cookie is `HttpOnly` — JavaScript cannot read it. Even a full XSS compromise can only make authenticated requests during the session, not exfiltrate the tokens themselves.

### Token refresh race condition (double-refresh)
**Attack:** Two concurrent requests both find an expired session and attempt to refresh simultaneously, causing one refresh token to be used twice (which triggers refresh token rotation revocation at many IdPs, ending the session).

**Mitigation:** bezzie uses a KV lock (`refresh-lock:`) with a short TTL. Only one refresh is attempted at a time; concurrent requests wait. This is a best-effort guard — see limitations below.

### PKCE state key collisions
**Attack:** KV key collisions between session keys and PKCE state keys cause session data to be misinterpreted.

**Mitigation:** All KV keys are namespaced by type: `session:`, `pkce:`, `discovery:`.

### Slow IdP / request timeout
**Attack:** A slow or unresponsive IdP hangs Worker requests indefinitely.

**Mitigation:** All outbound fetches to the IdP (discovery, token exchange, revocation, JWKS) use `AbortSignal.timeout(5000)` — 5 second timeout.

### Auth-endpoint flood / storage quota exhaustion
**Attack:** Every unauthenticated `GET /login` writes a PKCE-state entry to the session adapter. On Cloudflare KV's free tier (1,000 writes/day), a trivial unauthenticated loop against `/login` exhausts that quota in minutes — after which `adapter.set` starts failing and nobody can log in. This denies login to real users; it does not require guessing any credential.

**Mitigation:** `/login` and `/callback` are rate-limited by client IP by default (`rateLimit` config), with an in-memory pre-filter in front of the adapter-backed counter so the counters themselves don't consume the quota they protect. Fails open on any counter-store error. See the README's Security section.

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

### Refresh token rotation race (edge case)
The KV lock is best-effort. Under extreme concurrency or KV latency, two refreshes could both slip through the lock window. This is unlikely in practice and the worst case is an extra refresh (not a security breach, unless the IdP uses one-time refresh tokens without rotation overlap).

### Upstream API token validation
bezzie forwards access tokens to upstream APIs in `Authorization: Bearer` headers. **It is the upstream's responsibility to validate these tokens** — verify the signature against the IdP's JWKS, check `iss`, `aud`, and `exp`. bezzie does not proxy validation results.

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

## Out of scope

- General DDoS / bot detection at the edge — use Cloudflare's built-in rate limiting rules and bot management. Bezzie's own `/login`/`/callback` rate limiting (above) is narrower and specific: it defends bezzie's own storage write quota, not the network or application layer generally.
- Credential-stuffing / password brute-force protection — the actual credential submission happens on the IdP's own page, which bezzie never sees. Use the IdP's own protection (e.g. Auth0 Attack Protection, Okta ThreatInsight).
- Multi-tenant isolation — the deploying application is responsible for tenant boundaries
- Phishing — bezzie cannot protect against a user being directed to a fake login page
