import { Hono } from 'hono'
import { setCookie } from 'hono/cookie'
import * as oauth from 'oauth4webapi'
import type { BezzieConfig } from './index'
import { SessionStore, type Session } from './session'

export function authRoutes(config: BezzieConfig) {
  const router = new Hono()
  const sessionStore = new SessionStore(config.kv)

  router.get('/login', async (c) => {
    const code_verifier = oauth.generateRandomCodeVerifier()
    const code_challenge = await oauth.calculatePKCECodeChallenge(code_verifier)
    const state = oauth.generateRandomState()

    // Store state and codeVerifier in KV
    await config.kv.put(`pkce:${state}`, code_verifier, { expirationTtl: 600 }) // 10 minutes

    const authorizationUrl = new URL(`https://${config.domain}/authorize`)
    authorizationUrl.searchParams.set('client_id', config.clientId)
    authorizationUrl.searchParams.set('response_type', 'code')
    authorizationUrl.searchParams.set('redirect_uri', `${config.baseUrl}/auth/callback`)
    authorizationUrl.searchParams.set('scope', 'openid profile email')
    authorizationUrl.searchParams.set('state', state)
    authorizationUrl.searchParams.set('code_challenge', code_challenge)
    authorizationUrl.searchParams.set('code_challenge_method', 'S256')
    if (config.audience) {
      authorizationUrl.searchParams.set('audience', config.audience)
    }

    return c.redirect(authorizationUrl.toString())
  })

  router.get('/callback', async (c) => {
    const state = c.req.query('state')
    const code = c.req.query('code')

    if (!state || !code) {
      return c.text('Missing state or code', 400)
    }

    const codeVerifier = await config.kv.get(`pkce:${state}`)
    if (!codeVerifier) {
      return c.text('Invalid or expired state', 400)
    }

    await config.kv.delete(`pkce:${state}`)

    const as = await oauth
      .discoveryRequest(new URL(`https://${config.domain}`))
      .then((response) => oauth.processDiscoveryResponse(new URL(`https://${config.domain}`), response))

    const client: oauth.Client = {
      client_id: config.clientId,
      client_secret: config.clientSecret,
      token_endpoint_auth_method: 'client_secret_post',
    }

    const response = await oauth.authorizationCodeGrantRequest(
      as,
      client,
      new URL(`${config.baseUrl}/auth/callback`),
      code,
      codeVerifier,
    )

    const result = await oauth.processAuthorizationCodeOpenIDResponse(as, client, response)
    if (oauth.isOAuth2Error(result)) {
      return c.text('OAuth 2.0 error', 400)
    }

    const { access_token, refresh_token, expires_in } = result
    const claims = oauth.getValidatedIdTokenClaims(result)

    const sessionId = crypto.randomUUID()
    const session: Session = {
      accessToken: access_token,
      refreshToken: refresh_token || '',
      expiresAt: Math.floor(Date.now() / 1000) + (expires_in || 3600),
      user: {
        sub: claims.sub,
        email: claims.email as string | undefined,
        ...claims,
      },
    }

    // TTL for session in KV. If expires_in is not provided, default to 1 hour.
    // In a real app, you might want this to be longer if using refresh tokens.
    await sessionStore.set(sessionId, session, expires_in || 3600)

    setCookie(c, 'sessionId', sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      path: '/',
    })

    return c.redirect('/')
  })

  return router
}
