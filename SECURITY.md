# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.x (pre-release) | ✅ Best effort |
| 1.x (stable, once released) | ✅ Full support |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities via GitHub's private vulnerability reporting:
👉 [Report a vulnerability](https://github.com/neilpmas/bezzie/security/advisories/new)

You can expect:
- **Acknowledgement** within 48 hours
- **Status update** within 7 days
- **Fix or mitigation** for critical issues within 30 days

## Threat Model

Bezzie implements the [OAuth 2.0 for Browser-Based Apps (BCP212)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps) pattern.

**What bezzie protects against:**
- JWTs in the browser (tokens are stored server-side in KV, never sent to the client)
- PKCE replay attacks (state is one-time-use, bound to a pre-login CSRF cookie)
- Login-CSRF (state is bound to a `__Host-pkce-csrf` cookie set at `/login`)
- Session fixation (pre-existing sessions are invalidated at `/callback`)
- Open redirects (the `returnTo` parameter is validated to be a relative path only)
- Token theft via XSS (the session cookie is `HttpOnly` — JavaScript cannot read it)
- Expired sessions (absolute 90-day expiry enforced independently of KV TTL)

**What bezzie does not protect against (out of scope):**
- Compromise of the Cloudflare KV namespace
- Compromise of the OAuth client secret
- Attacks against the Identity Provider itself
- Network-level attacks (TLS termination is handled by Cloudflare)
