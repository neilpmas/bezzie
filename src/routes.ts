import { Hono } from 'hono'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import * as oauth from 'oauth4webapi'
import type { Session, PKCEState } from './session'
import type { BezzieConfig } from './index'

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

export function authRoutes(config: BezzieConfig) {
  const router = new Hono()
  const sessionStore = config.adapter

  router.get('/login', async (c) => {
    const code_verifier = oauth.generateRandomCodeVerifier()
    const code_challenge = await oauth.calculatePKCECodeChallenge(code_verifier)
    const state = oauth.generateRandomState()

    const returnTo = c.req.query('returnTo')

    // Store state and codeVerifier in adapter
    await config.adapter.set(`pkce:${state}`, { codeVerifier: code_verifier, returnTo } as PKCEState, 600) // 10 minutes

    const as = await getAuthorizationServer(config)
    if (!as.authorization_endpoint) {
      return c.text('Missing authorization_endpoint', 500)
    }

    const authorizationUrl = new URL(as.authorization_endpoint)
    authorizationUrl.searchParams.set('client_id', config.clientId)
    authorizationUrl.searchParams.set('response_type', 'code')
    authorizationUrl.searchParams.set('redirect_uri', `${config.baseUrl}/auth/callback`)
    authorizationUrl.searchParams.set('scope', 'openid profile email offline_access')
    authorizationUrl.searchParams.set('state', state)
    authorizationUrl.searchParams.set('code_challenge', code_challenge)
    authorizationUrl.searchParams.set('code_challenge_method', 'S256')
    if (config.audience) {
      authorizationUrl.searchParams.set('audience', config.audience)
    }

    return c.redirect(authorizationUrl.toString())
  })

  router.get('/callback', async (c) => {
    const error = c.req.query('error')
    if (error) {
      return c.text(`OAuth error: ${error}`, 400)
    }
    const state = c.req.query('state')
    const code = c.req.query('code')

    if (!state || !code) {
      return c.text('Missing state or code', 400)
    }

    const stored = await config.adapter.get(`pkce:${state}`) as PKCEState
    if (!stored) {
      return c.text('Invalid or expired state', 400)
    }
    const { codeVerifier, returnTo } = stored

    await config.adapter.delete(`pkce:${state}`)

    const as = await getAuthorizationServer(config)

    const client: oauth.Client = {
      client_id: config.clientId,
      client_secret: config.clientSecret,
      token_endpoint_auth_method: 'client_secret_post',
    }

    const response = await oauth.authorizationCodeGrantRequest(
      as,
      client,
      new URL(c.req.url).searchParams,
      `${config.baseUrl}/auth/callback`,
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
        ...claims,
        sub: claims.sub,
        email: claims.email as string | undefined,
      },
    }

    // TTL for session in KV. Set to 30 days as per bug fix 3.
    await sessionStore.set(sessionId, session, 30 * 24 * 60 * 60)

    setCookie(c, 'sessionId', sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      path: '/',
    })

    if (returnTo && returnTo.startsWith('/') && !returnTo.startsWith('//')) {
      return c.redirect(returnTo)
    }

    return c.redirect('/')
  })

  router.get('/logout', async (c) => {
    const sessionId = getCookie(c, 'sessionId')
    if (sessionId) {
      await sessionStore.delete(sessionId)
    }

    deleteCookie(c, 'sessionId', {
      path: '/',
      secure: true,
    })

    const as = await getAuthorizationServer(config)

    let logoutUrl: URL
    if (config.providerHints?.logoutUrl) {
      logoutUrl = new URL(config.providerHints.logoutUrl)
      logoutUrl.searchParams.set('client_id', config.clientId)
      logoutUrl.searchParams.set('returnTo', config.baseUrl)
    } else if (as.end_session_endpoint) {
      logoutUrl = new URL(as.end_session_endpoint)
      logoutUrl.searchParams.set('client_id', config.clientId)
      logoutUrl.searchParams.set('post_logout_redirect_uri', config.baseUrl)
    } else {
      // If no endpoint found, we just redirect to base URL
      return c.redirect('/')
    }

    return c.redirect(logoutUrl.toString())
  })

  return router
}
