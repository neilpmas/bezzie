import type { MiddlewareHandler, Context } from 'hono'
import { getCookie } from 'hono/cookie'
import * as oauth from 'oauth4webapi'
import { getAuthorizationServer, type DiscoveryCache } from './discovery'
import type { Session, SessionAdapter } from './session'
import type { ResolvedBezzieConfig } from './index'

/**
 * Hono context variables provided by Bezzie middleware.
 * These are what downstream route handlers read from `c.var`.
 */
/**
 * Hono context variables guaranteed to be present in routes protected by `middleware()`.
 */
export type AuthenticatedVariables<TUser extends object = Record<string, unknown>> = {
  /**
   * The authenticated user's information.
   */
  user: Session<TUser>['user']
  /**
   * The current OAuth access token.
   */
  accessToken: string
}

/**
 * Hono context variables that may be present in routes using `optionalMiddleware()`.
 */
export type OptionalVariables<TUser extends object = Record<string, unknown>> = {
  /**
   * The authenticated user's information, if a valid session exists.
   */
  user?: Session<TUser>['user']
  /**
   * The current OAuth access token, if a valid session exists.
   */
  accessToken?: string
}

/**
 * Alias for `AuthenticatedVariables` — the common case for protected routes.
 */
export type Variables<TUser extends object = Record<string, unknown>> = AuthenticatedVariables<TUser>

/**
 * Context passed to the `onLogin` lifecycle hook.
 */
export interface LoginHookContext<TUser extends object = Record<string, unknown>> {
  user: Session<TUser>['user']
  sessionId: string
  tokens: { accessToken: string; expiresAt: number }
  isNewSession: boolean
  c: Context
}

/**
 * Context passed to the `onRefresh` lifecycle hook.
 */
export interface RefreshHookContext<TUser extends object = Record<string, unknown>> {
  user: Session<TUser>['user']
  sessionId: string
  previousExpiresAt: number
  newExpiresAt: number
  c: Context
}

/**
 * Context passed to the `onLogout` lifecycle hook.
 */
export interface LogoutHookContext<TUser extends object = Record<string, unknown>> {
  user: Session<TUser>['user']
  sessionId: string
  c: Context
}

/**
 * Context passed to the `onError` hook when a non-fatal lifecycle hook throws.
 */
export interface HookErrorContext {
  hook: 'onLogin' | 'onRefresh' | 'onLogout'
  c: Context
}

type AuthResult<TUser extends object = Record<string, unknown>> =
  | { type: 'authenticated'; user: Session<TUser>['user']; accessToken: string }
  | { type: 'unauthenticated' }
  | { type: 'expired' }

const REFRESH_RACE_RETRY_DELAY_MS = 250

/**
 * After an `invalid_grant` on refresh, look for a session that a concurrent
 * request has already refreshed (its access token differs from the one this
 * request started with). Checks immediately, then once more after a short
 * delay, since the winning request may not have written yet and eventually
 * consistent stores (Cloudflare KV) can lag. Returns null if none appears.
 */
async function findConcurrentlyRefreshedSession<TUser extends object>(
  store: SessionAdapter<TUser>,
  sessionId: string,
  staleAccessToken: string
): Promise<Session<TUser> | null> {
  for (let attempt = 0; attempt < 2; attempt++) {
    if (attempt > 0) {
      await new Promise((resolve) => setTimeout(resolve, REFRESH_RACE_RETRY_DELAY_MS))
    }
    const latest = await store.get(`session:${sessionId}`)
    if (latest && latest._type === 'session' && latest.accessToken !== staleAccessToken) {
      return latest
    }
  }
  return null
}

let warnedJwtValidationFallback = false

async function authenticate<TUser extends object = Record<string, unknown>>(
  c: Context,
  config: ResolvedBezzieConfig<TUser>,
  cache: DiscoveryCache
): Promise<AuthResult<TUser>> {
  const sessionStore = config.adapter

  // 1. Read the sessionId cookie from the request
  const secure = config.secureCookies !== false
  const sessionCookieName = config.cookieName ?? (secure ? '__Host-session' : 'session')
  const sessionId = getCookie(c, sessionCookieName)

  // 2. If no cookie → unauthenticated
  if (!sessionId) {
    return { type: 'unauthenticated' }
  }

  // 3. Look up the session in KV using SessionStore
  let session = await sessionStore.get(`session:${sessionId}`)

  // 4. If no session found, or it's a PKCE state or rate-limit counter
  // (neither of which is ever actually stored under a `session:` key, but
  // the adapter's return type covers all three) → unauthenticated.
  if (!session || session._type === 'pkce' || session._type === 'ratelimit') {
    return { type: 'unauthenticated' }
  }

  // 4.5 Check for absolute session expiry (90 days)
  const MAX_SESSION_AGE = 90 * 24 * 60 * 60 // 90 days
  if (Math.floor(Date.now() / 1000) - session.createdAt > MAX_SESSION_AGE) {
    await sessionStore.delete(`session:${sessionId}`)
    return { type: 'expired' }
  }

  const as = await getAuthorizationServer(config, cache)

  // 5. Check if the access token is expired (with configurable buffer)
  const nowSeconds = Date.now() / 1000
  if (session.expiresAt < nowSeconds + (config.refreshBufferSeconds ?? 60)) {
    if (!session.refreshToken) {
      // Nothing to refresh with (the provider issued no refresh token, e.g.
      // `offline_access` was not granted). Inside the refresh buffer the access
      // token is still usable, but once it has actually expired the session
      // is dead: keeping it "authenticated" for the rest of its KV lifetime
      // would only hand upstreams a token they will reject.
      if (session.expiresAt <= nowSeconds) {
        await sessionStore.delete(`session:${sessionId}`)
        return { type: 'unauthenticated' }
      }
    } else {
      try {
        // 6. If expired → use oauth4webapi to perform a refresh token grant
        const client: oauth.Client = { client_id: config.clientId }
        const clientAuth = oauth.ClientSecretPost(config.clientSecret)

        const response = await oauth.refreshTokenGrantRequest(as, client, clientAuth, session.refreshToken, { signal: AbortSignal.timeout(5000) })
        const result = await oauth.processRefreshTokenResponse(as, client, response)

        // Capture previous expiresAt before overwriting, for onRefresh hook.
        const previousExpiresAt = session.expiresAt
        // Update the session in KV with new tokens and new expiresAt
        session.accessToken = result.access_token
        if (result.refresh_token) {
          session.refreshToken = result.refresh_token
        }
        session.expiresAt = Math.floor(Date.now() / 1000) + (result.expires_in || 3600)

        await sessionStore.set(`session:${sessionId}`, session, config.sessionTtlSeconds ?? 30 * 24 * 60 * 60) // 30 days, matches initial session TTL

        if (config.onRefresh) {
          try {
            await config.onRefresh({
              user: session.user,
              sessionId,
              previousExpiresAt,
              newExpiresAt: session.expiresAt,
              c,
            })
          } catch (hookErr) {
            const handler = config.onError ?? ((e: unknown) => console.error('Bezzie: onRefresh hook threw:', e instanceof Error ? e.message : String(e)))
            handler(hookErr, { hook: 'onRefresh', c })
          }
        }
      } catch (err) {
        if (err instanceof oauth.ResponseBodyError && err.error === 'invalid_grant') {
          // The refresh token was rejected. Usually that means it is genuinely
          // dead (revoked, expired), but with rotating refresh tokens it can
          // also mean a concurrent request already redeemed it and stored a
          // fresh session. There is no cross-request lock, so look for that
          // before giving up.
          const refreshedSession = await findConcurrentlyRefreshedSession(sessionStore, sessionId, session.accessToken)
          if (!refreshedSession) {
            // Truly failed
            await sessionStore.delete(`session:${sessionId}`)
            return { type: 'unauthenticated' }
          }
          session = refreshedSession
        } else {
          // Timeout, network error, IdP 5xx, misconfiguration, or a storage
          // failure while saving the new tokens. None of these say the user's
          // refresh token is bad, so keep the session — deleting it would log
          // out everyone whose token expires during an IdP blip — and fail
          // only this request.
          console.warn('Bezzie: token refresh failed (session kept, request unauthenticated):', err instanceof Error ? err.message : String(err))
          return { type: 'unauthenticated' }
        }
      }
    }
  }

  // 8. Validate the JWT using JWKS (only if audience is set and validation is enabled)
  if (config.validateAccessToken !== false && config.audience) {
    try {
      // We need a Request object that has the Authorization header for validateJwtAccessToken
      const mockReq = new Request(c.req.raw.url, {
        headers: {
          Authorization: `Bearer ${session.accessToken}`,
        },
      })

      // S10: validateJwtAccessToken verifies the JWT signature via JWKS and
      // asserts the standard claims — `iss` matches the authorization server,
      // `aud` matches `config.audience` (passed as the third argument, the
      // expectedAudience parameter), and `exp`/`nbf`/`iat` are within bounds.
      await oauth.validateJwtAccessToken(as, mockReq, config.audience, { [oauth.jwksCache]: cache.jwksCache })
    } catch (err) {
      // 9. If JWT invalid → fallback to opaque token (pass through)
      // This allows Bezzie to work with providers that issue opaque access tokens
      // or if the JWT is not verifiable for some reason, but we still have a valid session.
      // Logged once per isolate: with opaque tokens this fails on every request.
      if (!warnedJwtValidationFallback) {
        warnedJwtValidationFallback = true
        console.warn(
          'Bezzie: JWT access token validation failed (falling back to session trust; further failures are not logged):',
          err instanceof Error ? err.message : String(err)
        )
      }
    }
  }

  return { type: 'authenticated', user: session.user, accessToken: session.accessToken }
}

export function middleware<TUser extends object = Record<string, unknown>>(
  config: ResolvedBezzieConfig<TUser>,
  cache: DiscoveryCache
): MiddlewareHandler<{ Variables: AuthenticatedVariables<TUser> }> {
  return async (c, next) => {
    const result = await authenticate(c, config, cache)

    if (result.type === 'unauthenticated') {
      return c.text('Unauthorized', 401)
    }

    if (result.type === 'expired') {
      return c.redirect(config.loginPath ?? config.routes?.login ?? '/auth/login')
    }

    // Attach the user and accessToken to Hono context
    c.set('user', result.user)
    c.set('accessToken', result.accessToken)

    // Call next()
    await next()
  }
}

/**
 * Middleware that sets user context if a session exists but always calls next().
 */
export function optionalMiddleware<TUser extends object = Record<string, unknown>>(
  config: ResolvedBezzieConfig<TUser>,
  cache: DiscoveryCache
): MiddlewareHandler<{ Variables: OptionalVariables<TUser> }> {
  return async (c, next) => {
    const result = await authenticate(c, config, cache)

    if (result.type === 'authenticated') {
      // Attach the user and accessToken to Hono context
      c.set('user', result.user)
      c.set('accessToken', result.accessToken)
    }

    // Always call next()
    await next()
  }
}
