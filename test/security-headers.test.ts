import { describe, it, expect, vi } from 'vitest'
import { createBezzie, MemoryAdapter, type PKCEState } from '../src'
import type { DiscoveryCache } from '../src/discovery'
import * as oauth from 'oauth4webapi'
import { Hono } from 'hono'

vi.mock('oauth4webapi', async () => {
  const actual = await vi.importActual('oauth4webapi')
  return {
    ...actual,
    discoveryRequest: vi.fn(),
    processDiscoveryResponse: vi.fn(),
    authorizationCodeGrantRequest: vi.fn(),
    processAuthorizationCodeResponse: vi.fn(),
    getValidatedIdTokenClaims: vi.fn(),
  }
})

function expectAuthHeaders(res: Response) {
  expect(res.headers.get('Cache-Control')).toBe('no-store')
  expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff')
  expect(res.headers.get('X-Frame-Options')).toBe('DENY')
  expect(res.headers.get('Content-Security-Policy')).toBe("frame-ancestors 'none'")
}

describe('Security headers on auth routes', () => {
  const adapter = new MemoryAdapter()
  const config = {
    issuer: 'https://test.auth0.com',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    adapter: () => adapter,
    baseUrl: 'https://app.test.com',
    rateLimit: { enabled: false },
  }

  const auth = createBezzie(config)
  const app = auth.routes()

  function resetDiscoveryCache() {
    ;(auth as unknown as { cache: DiscoveryCache }).cache.cachedAS = null
    ;(auth as unknown as { cache: DiscoveryCache }).cache.cacheExpiresAt = 0
  }

  it('sets headers on the login 302', async () => {
    resetDiscoveryCache()
    vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue({
      issuer: config.issuer,
      authorization_endpoint: `${config.issuer}/authorize`,
    } as oauth.AuthorizationServer)

    const res = await app.request('/login')
    expect(res.status).toBe(302)
    expectAuthHeaders(res)
  })

  it('sets headers on a callback error response (error=access_denied)', async () => {
    const res = await app.request('/callback?error=access_denied')
    expect(res.status).toBe(400)
    expectAuthHeaders(res)
  })

  it('sets headers on a callback bad-CSRF response', async () => {
    const state = 'headers-csrf-state'
    await adapter.set(
      `pkce:${state}`,
      {
        _type: 'pkce',
        codeVerifier: 'a'.repeat(43),
        csrfToken: 'expected-token',
        nonce: 'n',
      } as PKCEState,
      600
    )

    const res = await app.request(`/callback?state=${state}&code=abc`, {
      headers: { Cookie: '__Host-pkce-csrf=wrong-token' },
    })
    expect(res.status).toBe(400)
    expectAuthHeaders(res)
  })

  it('sets headers on the callback success 302', async () => {
    resetDiscoveryCache()
    const state = 'headers-success-state'
    const csrfToken = 'headers-success-csrf'
    await adapter.set(
      `pkce:${state}`,
      {
        _type: 'pkce',
        codeVerifier: 'a'.repeat(43),
        csrfToken,
        nonce: 'n',
      } as PKCEState,
      600
    )

    vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue({
      issuer: config.issuer,
    } as oauth.AuthorizationServer)
    vi.mocked(oauth.authorizationCodeGrantRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processAuthorizationCodeResponse).mockResolvedValue({
      access_token: 'at',
      expires_in: 3600,
      id_token: 'idt',
    } as oauth.TokenEndpointResponse)
    vi.mocked(oauth.getValidatedIdTokenClaims).mockReturnValue({
      sub: 'user-headers',
    } as unknown as oauth.IDToken)

    const res = await app.request(`/callback?state=${state}&code=abc`, {
      headers: { Cookie: `__Host-pkce-csrf=${csrfToken}` },
    })
    expect(res.status).toBe(302)
    expectAuthHeaders(res)
  })

  it('sets headers on the logout 302', async () => {
    resetDiscoveryCache()
    vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue({
      issuer: config.issuer,
    } as oauth.AuthorizationServer)

    const res = await app.request('/logout', { method: 'POST' })
    expect(res.status).toBe(302)
    expectAuthHeaders(res)
  })

  it('does not set these headers on a route mounted alongside the auth router', async () => {
    const outerApp = new Hono()
    outerApp.route('/auth', app)
    outerApp.get('/other', (c) => c.text('ok'))

    const res = await outerApp.request('/other')
    expect(res.status).toBe(200)
    expect(res.headers.get('Cache-Control')).not.toBe('no-store')
    expect(res.headers.get('X-Frame-Options')).toBeNull()
    expect(res.headers.get('Content-Security-Policy')).toBeNull()
  })

  it('merges into an app-wide CSP set before the auth router, rather than replacing it', async () => {
    const outerApp = new Hono()
    outerApp.use('*', async (c, next) => {
      c.header('Content-Security-Policy', "default-src 'self'; script-src 'self'")
      await next()
    })
    outerApp.route('/auth', app)

    const res = await outerApp.request('/auth/callback?error=access_denied')
    const csp = res.headers.get('Content-Security-Policy')
    expect(csp).toContain("default-src 'self'")
    expect(csp).toContain("script-src 'self'")
    expect(csp).toContain("frame-ancestors 'none'")
  })

  it('forces frame-ancestors to none even if the app set a weaker one', async () => {
    const outerApp = new Hono()
    outerApp.use('*', async (c, next) => {
      c.header('Content-Security-Policy', "default-src 'self'; frame-ancestors 'self'")
      await next()
    })
    outerApp.route('/auth', app)

    const res = await outerApp.request('/auth/callback?error=access_denied')
    const csp = res.headers.get('Content-Security-Policy')
    expect(csp).toContain("default-src 'self'")
    expect(csp).toContain("frame-ancestors 'none'")
    expect(csp).not.toContain("frame-ancestors 'self'")
  })
})
