import { Hono } from 'hono'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import * as oauth from 'oauth4webapi'
import { getAuthorizationServer, type DiscoveryCache } from './discovery'
import type { Session, PKCEState } from './session'
import type { BezzieConfig } from './index'

export function authRoutes<TUser extends Record<string, unknown> = Record<string, unknown>>(
  config: BezzieConfig<TUser>,
  cache: DiscoveryCache
) {
  const router = new Hono()
  const sessionStore = config.adapter

  router.get('/login', async (c) => {
    const code_verifier = oauth.generateRandomCodeVerifier()
    const code_challenge = await oauth.calculatePKCECodeChallenge(code_verifier)
    const state = oauth.generateRandomState()
    const csrfToken = oauth.generateRandomState()

    const returnTo = c.req.query('returnTo')

    // Store state, codeVerifier and csrfToken in adapter
    await config.adapter.set(`pkce:${state}`, { _type: 'pkce', codeVerifier: code_verifier, returnTo, csrfToken } as PKCEState, config.pkceStateTtlSeconds ?? 600) // 10 minutes

    // Bind the PKCE state to the user's browser session via a short-lived cookie
    // to prevent login-CSRF (S4).
    setCookie(c, '__Host-pkce-csrf', csrfToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      path: '/',
      maxAge: 600,
    })

    const as = await getAuthorizationServer(config, cache)
    if (!as.authorization_endpoint) {
      return c.text('Missing authorization_endpoint', 500)
    }

    const authorizationUrl = new URL(as.authorization_endpoint)
    authorizationUrl.searchParams.set('client_id', config.clientId)
    authorizationUrl.searchParams.set('response_type', 'code')
    authorizationUrl.searchParams.set('redirect_uri', `${config.baseUrl}/auth/callback`)
    authorizationUrl.searchParams.set('scope', (config.scopes ?? ['openid', 'profile', 'email', 'offline_access']).join(' '))
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
      const ERROR_MESSAGES: Record<string, string> = {
        access_denied: 'Access was denied.',
        temporarily_unavailable: 'The provider is temporarily unavailable. Please try again.',
        server_error: 'The provider returned a server error.',
      }
      return c.text(ERROR_MESSAGES[error] ?? 'Authentication failed.', 400)
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
    const { codeVerifier, returnTo, csrfToken: storedCsrfToken } = stored

    if (!codeVerifier || codeVerifier.length < 43) {
      return c.text('Invalid PKCE state', 400)
    }

    // Login-CSRF protection (S4): the cookie set at /login must match the
    // csrfToken stored alongside the PKCE state in KV.
    const cookieCsrfToken = getCookie(c, '__Host-pkce-csrf')
    if (!cookieCsrfToken || !storedCsrfToken || cookieCsrfToken !== storedCsrfToken) {
      return c.text('Invalid CSRF token', 400)
    }

    await config.adapter.delete(`pkce:${state}`)

    // Clear the CSRF cookie now that it has served its purpose.
    deleteCookie(c, '__Host-pkce-csrf', {
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'Strict',
    })

    const as = await getAuthorizationServer(config, cache)

    const client: oauth.Client = { client_id: config.clientId }
    const clientAuth = oauth.ClientSecretPost(config.clientSecret)

    const callbackParams = oauth.validateAuthResponse(
      as,
      client,
      new URL(c.req.url).searchParams,
      oauth.skipStateCheck, // bezzie validates state via KV lookup above
    )

    const response = await oauth.authorizationCodeGrantRequest(
      as,
      client,
      clientAuth,
      callbackParams,
      `${config.baseUrl}/auth/callback`,
      codeVerifier,
      { signal: AbortSignal.timeout(5000) },
    )

    let result: oauth.TokenEndpointResponse
    try {
      result = await oauth.processAuthorizationCodeResponse(as, client, response)
    } catch (err) {
      if (err instanceof oauth.ResponseBodyError) {
        return c.text('OAuth 2.0 error', 400)
      }
      throw err
    }

    const { access_token, refresh_token, expires_in, id_token } = result
    const claims = oauth.getValidatedIdTokenClaims(result)

    if (!claims) {
      return c.json({ error: 'id_token missing from token response' }, 500)
    }

    if (!refresh_token) {
      console.warn('Bezzie: refresh_token is missing from the token response. offline_access may not be enabled or supported by the provider.')
    }

    const sessionId = Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
    const session: Session<TUser> = {
      _type: 'session',
      accessToken: access_token,
      refreshToken: refresh_token,
      idToken: id_token,
      expiresAt: Math.floor(Date.now() / 1000) + (expires_in || 3600),
      createdAt: Math.floor(Date.now() / 1000),
      user: {
        ...claims,
        sub: claims.sub,
        email: claims.email as string | undefined,
      } as unknown as { sub: string; email?: string } & TUser,
    }

    // Prevent session fixation (S11): if the user already had a session cookie,
    // remove its KV entry before minting a fresh session.
    const existingSessionId = getCookie(c, config.cookieName ?? '__Host-session')
    if (existingSessionId) {
      await sessionStore.delete(`session:${existingSessionId}`)
    }

    // TTL for session in KV. Set to 30 days as per bug fix 3.
    await sessionStore.set(`session:${sessionId}`, session, config.sessionTtlSeconds ?? 30 * 24 * 60 * 60)

    setCookie(c, config.cookieName ?? '__Host-session', sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      path: '/',
      maxAge: config.sessionTtlSeconds ?? 30 * 24 * 60 * 60, // 30 days, matches KV session TTL
    })

    if (returnTo && returnTo.startsWith('/') && !returnTo.startsWith('//')) {
      return c.redirect(returnTo)
    }

    return c.redirect('/')
  })

  router.post('/logout', async (c) => {
    const sessionId = getCookie(c, config.cookieName ?? '__Host-session')
    let idToken: string | undefined
    if (sessionId) {
      const session = await sessionStore.get(`session:${sessionId}`)
      if (session && session._type === 'session') {
        idToken = (session as Session<TUser>).idToken
      }
      await sessionStore.delete(`session:${sessionId}`)
    }

    deleteCookie(c, config.cookieName ?? '__Host-session', {
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'Strict',
    })

    const as = await getAuthorizationServer(config, cache)

    let logoutUrl: URL
    if (config.providerHints?.logoutUrl) {
      logoutUrl = new URL(config.providerHints.logoutUrl)
      logoutUrl.searchParams.set('client_id', config.clientId)
      logoutUrl.searchParams.set('returnTo', config.baseUrl)
      if (idToken) {
        logoutUrl.searchParams.set('id_token_hint', idToken)
      }
    } else if (as.end_session_endpoint) {
      logoutUrl = new URL(as.end_session_endpoint)
      logoutUrl.searchParams.set('client_id', config.clientId)
      logoutUrl.searchParams.set('post_logout_redirect_uri', config.baseUrl)
      if (idToken) {
        logoutUrl.searchParams.set('id_token_hint', idToken)
      }
    } else {
      // If no endpoint found, we just redirect to base URL
      return c.redirect('/')
    }

    return c.redirect(logoutUrl.toString())
  })

  return router
}
