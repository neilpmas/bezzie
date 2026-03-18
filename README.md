# Portcullis

A BFF (Backend for Frontend) OAuth 2.0 auth library for Cloudflare Workers.

Implements the [OAuth 2.0 for Browser-Based Apps (BCP212)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps) pattern — JWTs never touch the browser. The BFF owns the OAuth flow and issues a session cookie to the frontend instead.

```
npm install portcullis
```

---

## Why

Most OAuth libraries hand tokens directly to the browser. BCP212 says you shouldn't — it's a significant attack surface. Portcullis keeps tokens server-side in Cloudflare KV and gives the browser a session cookie instead.

There's no open source library for this specific combination (BFF OAuth on Cloudflare Workers). The closest alternatives are Duende BFF (.NET) and `@auth0/nextjs-auth0` — both tied to specific frameworks.

---

## Usage

```typescript
import { createPortcullis } from 'portcullis'

const auth = createPortcullis({
  domain: 'your-tenant.auth0.com',
  clientId: 'xxx',
  clientSecret: env.AUTH0_CLIENT_SECRET,
  audience: 'https://api.yourproject.com',
  kv: env.SESSION_KV,
  baseUrl: 'https://app.yourproject.com',
})

// Mount auth routes
app.route('/auth', auth.routes())

// Protect API routes
app.use('/api/*', auth.middleware())
```

This gives you:

| Route | Description |
|---|---|
| `GET /auth/login` | Redirects to provider, initiates Authorization Code + PKCE flow |
| `GET /auth/callback` | Exchanges code for tokens, stores session in KV, sets cookie |
| `GET /auth/logout` | Clears session, clears cookie, redirects to provider logout |

---

## How It Works

### Login Flow

```
Browser → BFF /auth/login → Auth0 (Authorization Code + PKCE)
                                    │
                               code returned
                                    │
              BFF exchanges code → tokens stored in KV
              BFF issues HttpOnly session cookie → Browser
```

### Per-Request Flow

1. Browser sends request to BFF with session cookie
2. BFF looks up session in KV, retrieves access token
3. BFF validates JWT (via JWKS, using Web Crypto API)
4. If expired, BFF uses refresh token to get a new one and updates KV
5. BFF forwards request upstream with `Authorization: Bearer <token>`

### Session Storage

Sessions are stored in Cloudflare KV:

```
sessionId → { accessToken, refreshToken, expiresAt, user }
```

KV TTL is aligned with the refresh token lifetime. When the refresh token expires, the user must log in again.

---

## Configuration

| Option | Type | Description |
|---|---|---|
| `domain` | `string` | Your OAuth provider domain (e.g. `tenant.auth0.com`) |
| `clientId` | `string` | OAuth client ID |
| `clientSecret` | `string` | OAuth client secret — keep in Workers secrets |
| `audience` | `string` | API audience identifier |
| `kv` | `KVNamespace` | Cloudflare KV namespace binding for session storage |
| `baseUrl` | `string` | Base URL of your application (used for callback and redirects) |

---

## Cloudflare Setup

Add a KV namespace to your `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "SESSION_KV"
id = "<your-kv-namespace-id>"
```

Add your client secret as a Workers secret:

```sh
wrangler secret put AUTH0_CLIENT_SECRET
```

---

## Stack

| Component | Choice |
|---|---|
| Runtime | Cloudflare Workers |
| Router | Hono |
| OAuth | `oauth4webapi` (spec-compliant, no Node.js deps) |
| Session storage | Cloudflare KV |

---

## Status

Under active development. Not yet published to npm.

---

## License

MIT
