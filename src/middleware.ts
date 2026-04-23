import type { MiddlewareHandler, Context } from 'hono'
import { getCookie } from 'hono/cookie'
import * as oauth from 'oauth4webapi'
import { getAuthorizationServer, type DiscoveryCache } from './discovery'
import type { Session } from './session'
import type { BezzieConfig } from './index'

/**
 * Hono context variables provided by Bezzie middleware.
 * These are what downstream route handlers read from `c.var`.
 */
/**
 * Hono context variables guaranteed to be present in routes protected by `middleware()`.
 */
export type AuthenticatedVariables<TUser extends Record<string, unknown> = Record<string, unknown>> = {
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
export type OptionalVariables<TUser extends Record<string, unknown> = Record<string, unknown>> = {
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
export type Variables<TUser extends Record<string, unknown> = Record<string, unknown>> = AuthenticatedVariables<TUser>

type AuthResult<TUser extends Record<string, unknown> = Record<string, unknown>> =
  | { type: 'authenticated'; user: Session<TUser>['user']; accessToken: string }
  | { type: 'unauthenticated' }
  | { type: 'expired' }

async function authenticate<TUser extends Record<string, unknown> = Record<string, unknown>>(
  c: Context,
  config: BezzieConfig<TUser>,
  cache: DiscoveryCache
): Promise<AuthResult<TUser>> {
  const sessionStore = config.adapter

  // 1. Read the sessionId cookie from the request
  const sessionId = getCookie(c, config.cookieName ?? '__Host-session')

  // 2. If no cookie → unauthenticated
  if (!sessionId) {
    return { type: 'unauthenticated' }
  }

  // 3. Look up the session in KV using SessionStore
  let session = await sessionStore.get(`session:${sessionId}`)

  // 4. If no session found or it's a PKCE state → unauthenticated
  if (!session || session._type === 'pkce') {
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
  if (session.expiresAt < Date.now() / 1000 + (config.refreshBufferSeconds ?? 60)) {
    if (session.refreshToken) {
      try {
        // 6. If expired → use oauth4webapi to perform a refresh token grant
        const client: oauth.Client = { client_id: config.clientId }
        const clientAuth = oauth.ClientSecretPost(config.clientSecret)

        const response = await oauth.refreshTokenGrantRequest(as, client, clientAuth, session.refreshToken, { signal: AbortSignal.timeout(5000) })

        try {
          const result = await oauth.processRefreshTokenResponse(as, client, response)
          // Update the session in KV with new tokens and new expiresAt
          session.accessToken = result.access_token
          if (result.refresh_token) {
            session.refreshToken = result.refresh_token
          }
          session.expiresAt = Math.floor(Date.now() / 1000) + (result.expires_in || 3600)

          await sessionStore.set(`session:${sessionId}`, session, config.sessionTtlSeconds ?? 30 * 24 * 60 * 60) // 30 days, matches initial session TTL
        } catch (err) {
          if (err instanceof oauth.ResponseBodyError && err.error === 'invalid_grant') {
            // Potential race condition: another request might have already refreshed this token
            const refreshedSession = await sessionStore.get(`session:${sessionId}`)
            if (
              refreshedSession &&
              refreshedSession._type === 'session' &&
              refreshedSession.accessToken !== session.accessToken
            ) {
              // Someone else already refreshed it! Use that session.
              session = refreshedSession
            } else {
              // Truly failed
              await sessionStore.delete(`session:${sessionId}`)
              return { type: 'unauthenticated' }
            }
          } else {
            await sessionStore.delete(`session:${sessionId}`)
            return { type: 'unauthenticated' }
          }
        }
      } catch {
        await sessionStore.delete(`session:${sessionId}`)
        return { type: 'unauthenticated' }
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

      await oauth.validateJwtAccessToken(as, mockReq, config.audience, { [oauth.jwksCache]: cache.jwksCache })
    } catch (err) {
      // 9. If JWT invalid → fallback to opaque token (pass through)
      // This allows Bezzie to work with providers that issue opaque access tokens
      // or if the JWT is not verifiable for some reason, but we still have a valid session.
      console.warn('Bezzie: JWT access token validation failed (falling back to session trust):', err instanceof Error ? err.message : String(err))
    }
  }

  return { type: 'authenticated', user: session.user, accessToken: session.accessToken }
}

export function middleware<TUser extends Record<string, unknown> = Record<string, unknown>>(
  config: BezzieConfig<TUser>,
  cache: DiscoveryCache
): MiddlewareHandler<{ Variables: AuthenticatedVariables<TUser> }> {
  return async (c, next) => {
    const result = await authenticate(c, config, cache)

    if (result.type === 'unauthenticated') {
      return c.text('Unauthorized', 401)
    }

    if (result.type === 'expired') {
      return c.redirect(config.loginPath ?? '/auth/login')
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
export function optionalMiddleware<TUser extends Record<string, unknown> = Record<string, unknown>>(
  config: BezzieConfig<TUser>,
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
