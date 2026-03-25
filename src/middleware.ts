import type { MiddlewareHandler } from 'hono'
import { getCookie } from 'hono/cookie'
import * as oauth from 'oauth4webapi'
import { getAuthorizationServer, type DiscoveryCache } from './discovery'
import type { Session } from './session'
import type { BezzieConfig } from './index'

/**
 * Hono context variables provided by Bezzie middleware.
 * These are what downstream route handlers read from `c.var`.
 */
export type Variables = {
  /**
   * The authenticated user's information.
   */
  user: Session['user']
  /**
   * The current OAuth access token.
   */
  accessToken: string
}

const jwksCache: oauth.JWKSCacheInput = {}

export function middleware(config: BezzieConfig, cache: DiscoveryCache): MiddlewareHandler<{ Variables: Variables }> {
  const sessionStore = config.adapter

  return async (c, next) => {
    // 1. Read the sessionId cookie from the request
    const sessionId = getCookie(c, '__Host-session')

    // 2. If no cookie → return 401
    if (!sessionId) {
      return c.text('Unauthorized', 401)
    }

    // 3. Look up the session in KV using SessionStore
    let session = await sessionStore.get(sessionId)

    // 4. If no session found or it's a PKCE state → return 401
    if (!session || 'codeVerifier' in session) {
      return c.text('Unauthorized', 401)
    }

    // 4.5 Check for absolute session expiry (90 days)
    const MAX_SESSION_AGE = 90 * 24 * 60 * 60 // 90 days
    if (Math.floor(Date.now() / 1000) - session.createdAt > MAX_SESSION_AGE) {
      await sessionStore.delete(sessionId)
      return c.redirect(config.loginPath ?? '/auth/login')
    }

    const as = await getAuthorizationServer(config, cache)

    // 5. Check if the access token is expired (with 60s buffer)
    if (session.expiresAt < (Date.now() / 1000) + 60) {
      try {
        // 6. If expired → use oauth4webapi to perform a refresh token grant
        const client: oauth.Client = {
          client_id: config.clientId,
          client_secret: config.clientSecret,
          token_endpoint_auth_method: 'client_secret_post',
        }

        const response = await oauth.refreshTokenGrantRequest(as, client, session.refreshToken)
        const result = await oauth.processRefreshTokenResponse(as, client, response)

        if (oauth.isOAuth2Error(result)) {
          if (result.error === 'invalid_grant') {
            // Potential race condition: another request might have already refreshed this token
            const refreshedSession = await sessionStore.get(sessionId)
            if (
              refreshedSession &&
              !('codeVerifier' in refreshedSession) &&
              refreshedSession.accessToken !== session.accessToken
            ) {
              // Someone else already refreshed it! Use that session.
              session = refreshedSession
            } else {
              // Truly failed
              await sessionStore.delete(sessionId)
              return c.text('Unauthorized', 401)
            }
          } else {
            await sessionStore.delete(sessionId)
            return c.text('Unauthorized', 401)
          }
        } else {
          // Update the session in KV with new tokens and new expiresAt
          session.accessToken = result.access_token
          if (result.refresh_token) {
            session.refreshToken = result.refresh_token
          }
          session.expiresAt = Math.floor(Date.now() / 1000) + (result.expires_in || 3600)

          await sessionStore.set(sessionId, session, 30 * 24 * 60 * 60) // 30 days, matches initial session TTL
        }
      } catch {
        await sessionStore.delete(sessionId)
        return c.text('Unauthorized', 401)
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

        await oauth.validateJwtAccessToken(as, mockReq, config.audience, { [oauth.jwksCache]: jwksCache })
      } catch {
        // 9. If JWT invalid → return 401
        return c.text('Unauthorized', 401)
      }
    }

    // 10. Attach the user and accessToken to Hono context
    c.set('user', session.user)
    c.set('accessToken', session.accessToken)

    // 12. Call next()
    await next()
  }
}
