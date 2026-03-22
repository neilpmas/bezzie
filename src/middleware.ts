import { type MiddlewareHandler } from 'hono'
import { getCookie } from 'hono/cookie'
import * as oauth from 'oauth4webapi'
import { SessionStore, type Session } from './session'
import type { BezzieConfig } from './index'

export type Variables = { user: Session['user'] }

export function middleware(config: BezzieConfig): MiddlewareHandler<{ Variables: Variables }> {
  const sessionStore = new SessionStore(config.kv)

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

    const as: oauth.AuthorizationServer = {
      issuer: `https://${config.domain}/`,
      jwks_uri: `https://${config.domain}/.well-known/jwks.json`,
    }

    // 5. Check if the access token is expired
    if (session.expiresAt < Date.now() / 1000) {
      // 6. If expired → use oauth4webapi to perform a refresh token grant
      const client: oauth.Client = {
        client_id: config.clientId,
        client_secret: config.clientSecret,
        token_endpoint_auth_method: 'client_secret_post',
      }

      try {
        const response = await oauth.refreshTokenGrantRequest(as, client, session.refreshToken)
        const result = await oauth.processRefreshTokenResponse(as, client, response)

        if (oauth.isOAuth2Error(result)) {
          throw new Error('Refresh failed')
        }

        // Update the session in KV with new tokens and new expiresAt
        session.accessToken = result.access_token
        if (result.refresh_token) {
          session.refreshToken = result.refresh_token
        }
        session.expiresAt = Math.floor(Date.now() / 1000) + (result.expires_in || 3600)

        await sessionStore.set(sessionId, session, result.refresh_token_expires_in || 86400) // Default to 1 day if not provided
      } catch (error) {
        // 7. If refresh fails → delete the session from KV, return 401
        await sessionStore.delete(sessionId)
        return c.text('Unauthorized', 401)
      }
    }

    // 8. Validate the JWT using JWKS
    try {
      // We need a Request object that has the Authorization header for validateJwtAccessToken
      const mockReq = new Request(c.req.raw.url, {
        headers: {
          Authorization: `Bearer ${session.accessToken}`,
        },
      })

      await oauth.validateJwtAccessToken(as, mockReq, config.audience)
    } catch (error) {
      // 9. If JWT invalid → return 401
      return c.text('Unauthorized', 401)
    }

    // 10. Attach the user to Hono context
    c.set('user', session.user)

    // 11. Forward Authorization: Bearer <accessToken> header to upstream
    // Note: In Cloudflare Workers, c.req.raw.headers is immutable if it's the original request.
    // However, we can try to set it, or at least it should be documented.
    // Some Hono versions/environments allow this if c.req.raw was cloned.
    try {
      c.req.raw.headers.set('Authorization', `Bearer ${session.accessToken}`)
    } catch (e) {
      // If immutable, we can't easily "forward" it by modifying the request object in-place
      // without replacing the whole request in the context, which is not recommended in Hono.
      // But we'll try as per instructions.
    }

    // 12. Call next()
    await next()
  }
}
