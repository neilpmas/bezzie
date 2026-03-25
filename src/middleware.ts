import type { MiddlewareHandler } from 'hono'
import { getCookie } from 'hono/cookie'
import * as oauth from 'oauth4webapi'
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
let cachedAS: oauth.AuthorizationServer | null = null
let cacheExpiresAt = 0

async function getAuthorizationServer(config: BezzieConfig): Promise<oauth.AuthorizationServer> {
  if (cachedAS && Date.now() < cacheExpiresAt) return cachedAS
  const issuerUrl = new URL(config.issuer)
  const response = await oauth.discoveryRequest(issuerUrl)
  const as = await oauth.processDiscoveryResponse(issuerUrl, response)
  cachedAS = config.providerHints?.tokenEndpoint
    ? { ...as, token_endpoint: config.providerHints.tokenEndpoint }
    : as
  cacheExpiresAt = Date.now() + 60 * 60 * 1000 // 1 hour
  return cachedAS
}

export function _resetDiscoveryCache() {
  cachedAS = null
  cacheExpiresAt = 0
}

export function middleware(config: BezzieConfig): MiddlewareHandler<{ Variables: Variables }> {
  const sessionStore = config.adapter

  return async (c, next) => {
    // 1. Read the sessionId cookie from the request
    const sessionId = getCookie(c, 'sessionId')

    // 2. If no cookie → return 401
    if (!sessionId) {
      return c.text('Unauthorized', 401)
    }

    // 3. Look up the session in KV using SessionStore
    const session = await sessionStore.get(sessionId)

    // 4. If no session found → return 401
    if (!session) {
      return c.text('Unauthorized', 401)
    }

    const as = await getAuthorizationServer(config)

    // 5. Check if the access token is expired (with 60s buffer)
    if (session.expiresAt < (Date.now() / 1000) + 60) {
      // 6. If expired → use oauth4webapi to perform a refresh token grant
      const client: oauth.Client = {
        client_id: config.clientId,
        client_secret: config.clientSecret,
        token_endpoint_auth_method: 'client_secret_post',
      }

      const response = await oauth.refreshTokenGrantRequest(as, client, session.refreshToken)
      const result = await oauth.processRefreshTokenResponse(as, client, response)

      if (oauth.isOAuth2Error(result)) {
        await sessionStore.delete(sessionId)
        return c.text('Unauthorized', 401)
      }

      // Update the session in KV with new tokens and new expiresAt
      session.accessToken = result.access_token
      if (result.refresh_token) {
        session.refreshToken = result.refresh_token
      }
      session.expiresAt = Math.floor(Date.now() / 1000) + (result.expires_in || 3600)

      await sessionStore.set(sessionId, session, 30 * 24 * 60 * 60) // 30 days, matches initial session TTL
    }

    // 8. Validate the JWT using JWKS
    try {
      // We need a Request object that has the Authorization header for validateJwtAccessToken
      const mockReq = new Request(c.req.raw.url, {
        headers: {
          Authorization: `Bearer ${session.accessToken}`,
        },
      })

      await oauth.validateJwtAccessToken(as, mockReq, config.audience ?? '', { [oauth.jwksCache]: jwksCache })
    } catch (error) {
      // 9. If JWT invalid → return 401
      return c.text('Unauthorized', 401)
    }

    // 10. Attach the user and accessToken to Hono context
    c.set('user', session.user)
    c.set('accessToken', session.accessToken)

    // 12. Call next()
    await next()
  }
}
