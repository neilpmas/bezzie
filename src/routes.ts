import { Hono, type Context, type Next } from 'hono'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import * as oauth from 'oauth4webapi'
import { getAuthorizationServer, type DiscoveryCache } from './discovery'
import type { Session, PKCEState } from './session'
import type { ResolvedBezzieConfig } from './index'
import { checkRateLimit, getClientIp } from './ratelimit'

export function authRoutes<TUser extends Record<string, unknown> = Record<string, unknown>>(
  config: ResolvedBezzieConfig<TUser>,
  cache: DiscoveryCache
) {
  const router = new Hono()
  const sessionStore = config.adapter
  const secure = config.secureCookies !== false
  const pkceCookieName = secure ? '__Host-pkce-csrf' : 'pkce-csrf'
  const sessionCookieName = config.cookieName ?? (secure ? '__Host-session' : 'session')

  // Every response from this router carries either single-use OAuth flow
  // material (state, code, cookies) or a session cookie. None of it is ever
  // safe to cache or frame, and that is not a choice the consuming app gets
  // to make — so these are unconditional, with no config surface. Registered
  // first so it wraps every downstream response, including the rate-limit
  // 429 and the error-path c.text(...) returns below.
  //
  // The CSP line merges into whatever policy is already on the response
  // rather than replacing it outright — an app-wide CSP set via middleware
  // mounted before this router (the common case) must survive here, not get
  // wiped by frame-ancestors alone. frame-ancestors itself is still forced
  // to 'none' unconditionally (any existing frame-ancestors directive from
  // the app is dropped and replaced), since that's the one thing here with
  // no config surface. Note this can't defend against an app that sets its
  // own CSP via middleware wrapping *outside* this router and does so
  // unconditionally after calling next() — that runs after this middleware
  // in Hono's onion model and can still clobber it. An app merging its own
  // CSP the same way (read-then-append, not blind `.set()`) is unaffected.
  router.use('*', async (c, next) => {
    await next()
    c.res.headers.set('Cache-Control', 'no-store')
    c.res.headers.set('X-Content-Type-Options', 'nosniff')
    c.res.headers.set('X-Frame-Options', 'DENY')

    const directives = (c.res.headers.get('Content-Security-Policy') ?? '')
      .split(';')
      .map((directive) => directive.trim())
      .filter((directive) => directive.length > 0 && !directive.toLowerCase().startsWith('frame-ancestors'))
    directives.push("frame-ancestors 'none'")
    c.res.headers.set('Content-Security-Policy', directives.join('; '))
  })

  // Flood and quota protection (not brute-force protection — see README
  // security section) on /login and /callback specifically: those are the
  // routes that perform an adapter write (the PKCE state) for every
  // unauthenticated request. /logout only reads/deletes an existing session
  // and is not the DoS vector this defends against, so it is left
  // unlimited. Fails open on any counter-store error.
  if (config.rateLimit?.enabled !== false) {
    const rateLimitAmount = config.rateLimit?.limit ?? 10
    const rateLimitWindowSeconds = config.rateLimit?.windowSeconds ?? 120
    const trustProxyHeaders = config.rateLimit?.trustProxyHeaders ?? false
    // Namespaced by limit/window so this never collides with a differently
    // configured limiter sharing the same adapter (e.g. auth.rateLimiter()
    // on the app's own routes).
    const bucketPrefix = `auth:${rateLimitAmount}:${rateLimitWindowSeconds}`

    const rateLimitMiddleware = async (c: Context, next: Next) => {
      const ip = getClientIp(c, trustProxyHeaders)
      if (!ip) {
        // No trustworthy IP to key on — skip limiting rather than lumping
        // every such client into one shared bucket (see getClientIp).
        return next()
      }
      const allowed = await checkRateLimit(config.adapter, `${bucketPrefix}:${ip}`, rateLimitAmount, rateLimitWindowSeconds)
      if (!allowed) {
        c.header('Retry-After', String(rateLimitWindowSeconds))
        return c.text('Too many requests', 429)
      }
      return next()
    }

    router.use(config.routes?.login ?? '/login', rateLimitMiddleware)
    router.use(config.routes?.callback ?? '/callback', rateLimitMiddleware)
  }

  router.get(config.routes?.login ?? '/login', async (c) => {
    const code_verifier = oauth.generateRandomCodeVerifier()
    const code_challenge = await oauth.calculatePKCECodeChallenge(code_verifier)
    // oauth.generateRandomState() uses crypto.getRandomValues — cryptographically random,
    // not sequential or time-based. Safe to use as an anti-CSRF state value.
    const state = oauth.generateRandomState()
    const csrfToken = oauth.generateRandomState()
    // S8: OIDC nonce — bound to this login flow, verified in /callback against
    // the `nonce` claim of the returned ID token to prevent replay.
    const nonce = oauth.generateRandomState()

    const returnTo = c.req.query('returnTo')

    // Store state, codeVerifier, csrfToken, and nonce in adapter
    await config.adapter.set(`pkce:${state}`, { _type: 'pkce', codeVerifier: code_verifier, returnTo, csrfToken, nonce } as PKCEState, config.pkceStateTtlSeconds ?? 600) // 10 minutes

    // Bind the PKCE state to the user's browser session via a short-lived cookie
    // to prevent login-CSRF (S4).
    setCookie(c, pkceCookieName, csrfToken, {
      httpOnly: true,
      secure,
      sameSite: 'Lax', // Must be Lax — Strict blocks cross-site redirects from the IdP
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
    authorizationUrl.searchParams.set('redirect_uri', `${config.baseUrl}${config.routes?.callback ?? '/auth/callback'}`)
    authorizationUrl.searchParams.set('scope', (config.scopes ?? ['openid', 'profile', 'email', 'offline_access']).join(' '))
    authorizationUrl.searchParams.set('state', state)
    authorizationUrl.searchParams.set('code_challenge', code_challenge)
    authorizationUrl.searchParams.set('code_challenge_method', 'S256')
    authorizationUrl.searchParams.set('nonce', nonce)
    if (config.audience) {
      authorizationUrl.searchParams.set('audience', config.audience)
    }

    if (!secure) {
      const requestUrl = new URL(c.req.url)
      if (requestUrl.hostname !== 'localhost' && requestUrl.hostname !== '127.0.0.1') {
        console.warn('Bezzie: secureCookies is disabled on a non-localhost host. This is insecure — cookies will not have the Secure flag or __Host- prefix. Do not use this in production.')
      }
    }

    return c.redirect(authorizationUrl.toString())
  })

  router.get(config.routes?.callback ?? '/callback', async (c) => {
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
    const { codeVerifier, returnTo, csrfToken: storedCsrfToken, nonce: storedNonce } = stored

    if (!codeVerifier || codeVerifier.length < 43) {
      return c.text('Invalid PKCE state', 400)
    }

    // Login-CSRF protection (S4): the cookie set at /login must match the
    // csrfToken stored alongside the PKCE state in KV.
    const cookieCsrfToken = getCookie(c, pkceCookieName)
    if (!cookieCsrfToken || !storedCsrfToken || cookieCsrfToken !== storedCsrfToken) {
      return c.text('Invalid CSRF token', 400)
    }

    await config.adapter.delete(`pkce:${state}`)

    // Clear the CSRF cookie now that it has served its purpose.
    deleteCookie(c, pkceCookieName, {
      path: '/',
      secure,
      httpOnly: true,
      sameSite: 'Lax',
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
      `${config.baseUrl}${config.routes?.callback ?? '/auth/callback'}`,
      codeVerifier,
      { signal: AbortSignal.timeout(5000) },
    )

    let result: oauth.TokenEndpointResponse
    try {
      // S8: pass expectedNonce so oauth4webapi verifies the ID token `nonce`
      // claim matches the value we sent in the authorization request.
      result = await oauth.processAuthorizationCodeResponse(as, client, response, {
        expectedNonce: storedNonce,
      })
    } catch (err) {
      if (err instanceof oauth.ResponseBodyError) {
        console.error('Bezzie: OAuth 2.0 token exchange error:', err)
        return c.text('OAuth 2.0 error', 400)
      }
      console.error('Bezzie: processAuthorizationCodeResponse failed (possible nonce mismatch):', err)
      return c.text('Invalid ID token', 400)
    }

    const { access_token, refresh_token, expires_in, id_token } = result
    const claims = oauth.getValidatedIdTokenClaims(result)

    if (!claims) {
      console.error('Bezzie: id_token missing from token response')
      return c.text('Authentication failed', 500)
    }

    if (!refresh_token) {
      console.warn('Bezzie: refresh_token is missing from the token response. offline_access may not be enabled or supported by the provider.')
    }

    const sessionId = Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')

    let mappedUser: { sub: string; email?: string } & TUser

    if (config.mapClaims) {
      try {
        const mapped = await config.mapClaims(claims)
        mappedUser = {
          ...mapped,
          sub: (claims as { sub: string }).sub,
          email: (claims as { email?: string }).email,
        } as { sub: string; email?: string } & TUser
      } catch (err) {
        // mapClaims threw — abort login, clean up
        deleteCookie(c, sessionCookieName, {
          path: '/',
          secure,
          httpOnly: true,
          sameSite: 'Lax',
        })
        console.error(
          'Bezzie: mapClaims threw, aborting login:',
          err instanceof Error ? err.message : String(err)
        )
        return c.text('Login failed', 500)
      }
    } else {
      mappedUser = {
        ...claims,
        sub: claims.sub,
        email: claims.email as string | undefined,
      } as unknown as { sub: string; email?: string } & TUser
    }

    const session: Session<TUser> = {
      _type: 'session',
      accessToken: access_token,
      refreshToken: refresh_token,
      idToken: id_token,
      expiresAt: Math.floor(Date.now() / 1000) + (expires_in || 3600),
      createdAt: Math.floor(Date.now() / 1000),
      user: mappedUser,
    }

    // Prevent session fixation (S11): if the user already had a session cookie,
    // remove its KV entry before minting a fresh session.
    const existingSessionId = getCookie(c, sessionCookieName)
    if (existingSessionId) {
      await sessionStore.delete(`session:${existingSessionId}`)
    }

    // TTL for session in KV. Set to 30 days as per bug fix 3.
    await sessionStore.set(`session:${sessionId}`, session, config.sessionTtlSeconds ?? 30 * 24 * 60 * 60)

    // SameSite=Lax is required here: the callback 302 is the tail of a cross-site
    // navigation chain from the IdP, so browsers will not attach Strict cookies on
    // the follow-up request. Lax still protects against CSRF on unsafe methods.
    setCookie(c, sessionCookieName, sessionId, {
      httpOnly: true,
      secure,
      sameSite: 'Lax',
      path: '/',
      maxAge: config.sessionTtlSeconds ?? 30 * 24 * 60 * 60, // 30 days, matches KV session TTL
    })

    if (config.onLogin) {
      try {
        await config.onLogin({
          user: session.user,
          sessionId,
          tokens: { accessToken: access_token, expiresAt: session.expiresAt },
          isNewSession: true,
          c,
        })
      } catch (err) {
        // onLogin errors bubble — abort login, clean up session
        await sessionStore.delete(`session:${sessionId}`)
        deleteCookie(c, sessionCookieName, {
          path: '/',
          secure,
          httpOnly: true,
          sameSite: 'Lax',
        })
        console.error(
          'Bezzie: onLogin hook threw, aborting login:',
          err instanceof Error ? err.message : String(err)
        )
        return c.text('Login failed', 500)
      }
    }

    if (returnTo && returnTo.startsWith('/') && !returnTo.startsWith('//')) {
      return c.redirect(returnTo)
    }

    return c.redirect(config.defaultReturnTo ?? '/')
  })

  router.post(config.routes?.logout ?? '/logout', async (c) => {
    const sessionId = getCookie(c, sessionCookieName)
    let idToken: string | undefined
    let refreshToken: string | undefined
    let loggedOutUser: Session<TUser>['user'] | undefined
    if (sessionId) {
      const session = await sessionStore.get(`session:${sessionId}`)
      if (session && session._type === 'session') {
        idToken = (session as Session<TUser>).idToken
        refreshToken = (session as Session<TUser>).refreshToken
        loggedOutUser = (session as Session<TUser>).user
      }
      await sessionStore.delete(`session:${sessionId}`)

      if (config.onLogout && loggedOutUser) {
        try {
          await config.onLogout({ user: loggedOutUser, sessionId, c })
        } catch (err) {
          const handler = config.onError ?? ((e: unknown) => console.error('Bezzie: onLogout hook threw:', e instanceof Error ? e.message : String(e)))
          handler(err, { hook: 'onLogout', c })
        }
      }
    }

    const as = await getAuthorizationServer(config, cache)

    // S12: best-effort revoke the refresh token at the IdP so the tokens are
    // invalidated server-side, not just locally. Wrapped in try/catch — a
    // revocation failure must not block the logout redirect.
    if (refreshToken && as.revocation_endpoint) {
      try {
        const client: oauth.Client = { client_id: config.clientId }
        const clientAuth = oauth.ClientSecretPost(config.clientSecret)
        const response = await oauth.revocationRequest(as, client, clientAuth, refreshToken, {
          signal: AbortSignal.timeout(5000),
        })
        await oauth.processRevocationResponse(response)
      } catch (err) {
        console.error('Bezzie: token revocation failed (continuing with logout):', err)
      }
    }

    deleteCookie(c, sessionCookieName, {
      path: '/',
      secure,
      httpOnly: true,
      sameSite: 'Lax',
    })

    let logoutUrl: URL
    if (config.providerOverrides?.logoutUrl) {
      logoutUrl = new URL(config.providerOverrides.logoutUrl)
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
