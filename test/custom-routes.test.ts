import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createBezzie, MemoryAdapter, type PKCEState } from '../src'
import type { DiscoveryCache } from '../src/discovery'
import * as oauth from 'oauth4webapi'
import { Hono } from 'hono'

// Mock oauth4webapi
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

describe('Custom Routes', () => {
  const adapter = new MemoryAdapter()
  const config = {
    issuer: 'https://test.auth0.com',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    adapter: () => adapter,
    baseUrl: 'https://app.test.com',
    routes: {
      login: '/custom-login',
      callback: '/custom-callback',
      logout: '/custom-logout',
    },
  }

  const auth = createBezzie(config)
  const app = auth.routes()

  beforeEach(() => {
    ;(auth as unknown as { cache: DiscoveryCache }).cache.cachedAS = null
    ;(auth as unknown as { cache: DiscoveryCache }).cache.cacheExpiresAt = 0
    vi.clearAllMocks()
  })

  it('uses custom login path', async () => {
    const mockAs = {
      issuer: config.issuer,
      authorization_endpoint: `${config.issuer}/authorize`,
    }
    vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(
      mockAs as oauth.AuthorizationServer
    )

    const res = await app.request('/custom-login')
    expect(res.status).toBe(302)
    const location = res.headers.get('Location')
    expect(location).toContain(`${config.issuer}/authorize`)
    // Should use the custom callback path in the redirect_uri
    expect(location).toContain(
      `redirect_uri=${encodeURIComponent(config.baseUrl + '/custom-callback')}`
    )
  })

  it('uses custom callback path', async () => {
    const state = 'test-state'
    const code = 'test-code'
    const codeVerifier = 'test-verifier-must-be-at-least-43-chars-long-aaa'
    const csrfToken = 'test-csrf-token'

    await adapter.set(
      `pkce:${state}`,
      { _type: 'pkce', codeVerifier, csrfToken } as PKCEState,
      600
    )

    const mockAs = { issuer: config.issuer }
    vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(
      mockAs as oauth.AuthorizationServer
    )
    vi.mocked(oauth.authorizationCodeGrantRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processAuthorizationCodeResponse).mockResolvedValue({
      access_token: 'mock-access-token',
      expires_in: 3600,
      id_token: 'mock-id-token',
    } as oauth.TokenEndpointResponse)
    vi.mocked(oauth.getValidatedIdTokenClaims).mockReturnValue({
      sub: 'user-123',
    } as unknown as oauth.IDToken)

    const res = await app.request(`/custom-callback?state=${state}&code=${code}`, {
      headers: { Cookie: `__Host-pkce-csrf=${csrfToken}` },
    })

    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toBe('/')
    
    // Verify redirect_uri sent to provider matched the custom path
    expect(oauth.authorizationCodeGrantRequest).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.anything(),
      expect.anything(),
      `${config.baseUrl}/custom-callback`,
      expect.anything(),
      expect.anything()
    )
  })

  it('uses custom logout path', async () => {
    const mockAs = {
      issuer: config.issuer,
      end_session_endpoint: `${config.issuer}/logout`,
    }
    vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(
      mockAs as oauth.AuthorizationServer
    )

    const res = await app.request('/custom-logout', { method: 'POST' })
    expect(res.status).toBe(302)
    const location = res.headers.get('Location')
    expect(location).toContain(`${config.issuer}/logout`)
  })

  it('middleware uses custom login path for redirects on expiry', async () => {
    const authApp = new Hono()
    authApp.use('/api/*', auth.middleware())
    authApp.get('/api/me', (c) => c.text('ok'))

    const sessionId = 'expired-session'
    const MAX_SESSION_AGE = 90 * 24 * 60 * 60
    await adapter.set(
      `session:${sessionId}`,
      {
        _type: 'session',
        accessToken: 'token',
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        createdAt: Math.floor(Date.now() / 1000) - (MAX_SESSION_AGE + 1),
        user: { sub: 'u' },
      },
      3600
    )

    const res = await authApp.request('/api/me', {
      headers: { Cookie: `__Host-session=${sessionId}` },
    })

    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toBe('/custom-login')
  })
})
