import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'
import { createBezzie, MemoryAdapter, type Bezzie, type Variables, type Session } from '../src'
import * as oauth from 'oauth4webapi'

// Mock oauth4webapi
vi.mock('oauth4webapi', async () => {
  const actual = await vi.importActual('oauth4webapi')
  return {
    ...actual,
    discoveryRequest: vi.fn(),
    processDiscoveryResponse: vi.fn(),
    refreshTokenGrantRequest: vi.fn(),
    processRefreshTokenResponse: vi.fn(),
    validateJwtAccessToken: vi.fn(),
  }
})

describe('Middleware', () => {
  let adapter: MemoryAdapter
  let auth: Bezzie
  let app: Hono<{ Variables: Variables }>
  const issuer = 'https://test.auth0.com'

  beforeEach(async () => {
    vi.clearAllMocks()
    adapter = new MemoryAdapter()
    const config = {
      issuer,
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      audience: 'https://api.test.com',
      adapter,
      baseUrl: 'https://app.test.com',
    }

    auth = createBezzie(config)
    app = new Hono<{ Variables: Variables }>()

    app.use('/api/*', auth.middleware())
    app.get('/api/me', (c) => {
      return c.json({ user: c.get('user'), accessToken: c.get('accessToken') })
    })

    // Default mock for discovery
    const mockAs = { issuer, jwks_uri: `${issuer}/jwks` }
    vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)
  })

  it('returns 401 with no cookie', async () => {
    const res = await app.request('/api/me')
    expect(res.status).toBe(401)
    expect(await res.text()).toBe('Unauthorized')
  })

  it('returns 401 with invalid session (not in KV)', async () => {
    const res = await app.request('/api/me', {
      headers: {
        Cookie: '__Host-session=non-existent',
      },
    })
    expect(res.status).toBe(401)
  })

  it('valid session passes through and sets user on context', async () => {
    const sessionId = 'test-session-id'
    const user = { sub: 'user-123', email: 'user@example.com' }
    await adapter.set(
      sessionId,
      {
        _type: 'session',
        accessToken: 'valid-token',
        refreshToken: 'valid-refresh',
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        createdAt: Math.floor(Date.now() / 1000),
        user,
      },
      3600
    )

    // Mock successful JWT validation
    vi.mocked(oauth.validateJwtAccessToken).mockResolvedValue({} as oauth.JWTAccessTokenClaims)

    const res = await app.request('/api/me', {
      headers: {
        Cookie: `__Host-session=${sessionId}`,
      },
    })

    expect(res.status).toBe(200)
    const data = (await res.json()) as { user?: Record<string, unknown>; accessToken?: string }
    expect(data.user).toEqual(user)
    expect(data.accessToken).toBe('valid-token')
  })

  it('expired access token triggers refresh, updates KV, passes through', async () => {
    const sessionId = 'test-session-id'
    const user = { sub: 'user-123' }
    await adapter.set(
      sessionId,
      {
        _type: 'session',
        accessToken: 'expired-token',
        refreshToken: 'valid-refresh',
        expiresAt: Math.floor(Date.now() / 1000) - 10, // expired 10s ago
        createdAt: Math.floor(Date.now() / 1000) - 1000,
        user,
      },
      86400
    )

    // Mock successful refresh
    vi.mocked(oauth.refreshTokenGrantRequest).mockResolvedValue({} as Response)
    vi.mocked(oauth.processRefreshTokenResponse).mockResolvedValue({
      access_token: 'new-token',
      refresh_token: 'new-refresh',
      expires_in: 3600,
      token_type: 'bearer',
    } as oauth.TokenEndpointResponse)
    vi.mocked(oauth.validateJwtAccessToken).mockResolvedValue({} as oauth.JWTAccessTokenClaims)

    const res = await app.request('/api/me', {
      headers: {
        Cookie: `__Host-session=${sessionId}`,
      },
    })

    expect(res.status).toBe(200)
    const data = (await res.json()) as { user?: Record<string, unknown>; accessToken?: string }
    expect(data.accessToken).toBe('new-token')

    // Check adapter updated
    const stored = (await adapter.get(sessionId)) as Session
    expect(stored.accessToken).toBe('new-token')
    expect(stored.refreshToken).toBe('new-refresh')
    expect(stored.expiresAt).toBeGreaterThan(Date.now() / 1000)
  })

  it('failed refresh deletes session and returns 401', async () => {
    const sessionId = 'test-session-id'
    await adapter.set(
      sessionId,
      {
        _type: 'session',
        accessToken: 'expired-token',
        refreshToken: 'invalid-refresh',
        expiresAt: Math.floor(Date.now() / 1000) - 10,
        createdAt: Math.floor(Date.now() / 1000) - 1000,
        user: { sub: '123' },
      },
      3600
    )

    // Mock failed refresh
    vi.mocked(oauth.refreshTokenGrantRequest).mockResolvedValue({} as Response)
    const error = new oauth.ResponseBodyError('invalid_grant', { 
      cause: { error: 'invalid_grant' },
      response: new Response() 
    })
    vi.mocked(oauth.processRefreshTokenResponse).mockRejectedValue(error)

    const res = await app.request('/api/me', {
      headers: {
        Cookie: `__Host-session=${sessionId}`,
      },
    })

    expect(res.status).toBe(401)
    
    // Check session deleted
    expect(await adapter.get(sessionId)).toBeNull()
  })

  it('invalid JWT returns 401', async () => {
    const sessionId = 'test-session-id'
    await adapter.set(
      sessionId,
      {
        _type: 'session',
        accessToken: 'invalid-jwt',
        refreshToken: 'refresh',
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        createdAt: Math.floor(Date.now() / 1000),
        user: { sub: '123' },
      },
      3600
    )

    // Mock JWT validation failure
    vi.mocked(oauth.validateJwtAccessToken).mockRejectedValue(new Error('Invalid token'))

    const res = await app.request('/api/me', {
      headers: {
        Cookie: `__Host-session=${sessionId}`,
      },
    })

    expect(res.status).toBe(401)
  })

  it('triggers refresh with 60s buffer', async () => {
    const sessionId = 'test-session-id'
    await adapter.set(
      sessionId,
      {
        _type: 'session',
        accessToken: 'near-expiry-token',
        refreshToken: 'valid-refresh',
        expiresAt: Math.floor(Date.now() / 1000) + 30, // expires in 30s
        createdAt: Math.floor(Date.now() / 1000) - 1000,
        user: { sub: '123' },
      },
      3600
    )

    vi.mocked(oauth.refreshTokenGrantRequest).mockResolvedValue({} as Response)
    vi.mocked(oauth.processRefreshTokenResponse).mockResolvedValue({
      access_token: 'new-token',
      expires_in: 3600,
      token_type: 'bearer',
    } as oauth.TokenEndpointResponse)
    vi.mocked(oauth.validateJwtAccessToken).mockResolvedValue({} as oauth.JWTAccessTokenClaims)

    const res = await app.request('/api/me', {
      headers: {
        Cookie: `__Host-session=${sessionId}`,
      },
    })

    expect(res.status).toBe(200)
    const data = (await res.json()) as { user?: Record<string, unknown>; accessToken?: string }
    expect(data.accessToken).toBe('new-token')
  })

  it('skips JWT validation when no audience is configured', async () => {
    // Create a new app/middleware with no audience
    const configNoAudience = {
      issuer,
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      // no audience
      adapter,
      baseUrl: 'https://app.test.com',
    }
    const authNoAudience = createBezzie(configNoAudience)
    const appNoAudience = new Hono()
    appNoAudience.use('/api/*', authNoAudience.middleware())
    appNoAudience.get('/api/me', (c) => c.json({ ok: true }))

    const sessionId = 'test-session-id'
    await adapter.set(sessionId, {
      _type: 'session',
      accessToken: 'valid-token',
      refreshToken: 'valid-refresh',
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      createdAt: Math.floor(Date.now() / 1000),
      user: { sub: '123' },
    }, 3600)

    const res = await appNoAudience.request('/api/me', {
      headers: {
        Cookie: `__Host-session=${sessionId}`,
      },
    })

    expect(res.status).toBe(200)
    // Should NOT have called validateJwtAccessToken
    expect(oauth.validateJwtAccessToken).not.toHaveBeenCalled()
  })

  it('skips JWT validation when validateAccessToken is false', async () => {
    const configWithValidateFalse = {
      issuer,
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      audience: 'https://api.test.com',
      adapter,
      baseUrl: 'https://app.test.com',
      validateAccessToken: false,
    }
    const authWithValidateFalse = createBezzie(configWithValidateFalse)
    const appWithValidateFalse = new Hono()
    appWithValidateFalse.use('/api/*', authWithValidateFalse.middleware())
    appWithValidateFalse.get('/api/me', (c) => c.json({ ok: true }))

    const sessionId = 'test-session-id'
    await adapter.set(sessionId, {
      _type: 'session',
      accessToken: 'opaque-token',
      refreshToken: 'valid-refresh',
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      createdAt: Math.floor(Date.now() / 1000),
      user: { sub: '123' },
    }, 3600)

    const res = await appWithValidateFalse.request('/api/me', {
      headers: {
        Cookie: `__Host-session=${sessionId}`,
      },
    })

    expect(res.status).toBe(200)
    expect(oauth.validateJwtAccessToken).not.toHaveBeenCalled()
  })

  it('re-reads session from store when refresh fails with invalid_grant (race condition)', async () => {
    const sessionId = 'test-session-id'
    const user = { sub: 'user-123' }
    const oldAccessToken = 'expired-token'
    const newAccessToken = 'already-refreshed-token'

    // Initial state: near-expiry token
    await adapter.set(
      sessionId,
      {
        _type: 'session',
        accessToken: oldAccessToken,
        refreshToken: 'valid-refresh',
        expiresAt: Math.floor(Date.now() / 1000) + 30, // expires in 30s
        createdAt: Math.floor(Date.now() / 1000),
        user,
      },
      86400
    )

    // Mock failed refresh with invalid_grant
    vi.mocked(oauth.refreshTokenGrantRequest).mockResolvedValue({} as Response)
    const error = new oauth.ResponseBodyError('invalid_grant', { 
      cause: { error: 'invalid_grant' },
      response: new Response() 
    })
    vi.mocked(oauth.processRefreshTokenResponse).mockRejectedValue(error)
    vi.mocked(oauth.validateJwtAccessToken).mockResolvedValue({} as oauth.JWTAccessTokenClaims)

    const originalGet = adapter.get.bind(adapter)
    let getCount = 0
    vi.spyOn(adapter, 'get').mockImplementation(async (id: string) => {
      getCount++
      const result = await originalGet(id)
      if (getCount === 1) {
        // After first GET, update adapter to simulate concurrent refresh by another request
        await adapter.set(
          id,
          {
            _type: 'session',
            accessToken: newAccessToken,
            refreshToken: 'new-refresh',
            expiresAt: Math.floor(Date.now() / 1000) + 3600,
            createdAt: Math.floor(Date.now() / 1000),
            user,
          },
          86400
        )
      }
      return result
    })

    const res = await app.request('/api/me', {
      headers: {
        Cookie: `__Host-session=${sessionId}`,
      },
    })

    expect(res.status).toBe(200)
    const data = (await res.json()) as { user?: Record<string, unknown>; accessToken?: string }
    expect(data.accessToken).toBe(newAccessToken)

    // Verify it was re-read (1st in middleware start, 2nd after invalid_grant)
    expect(getCount).toBe(2)
  })

  it('redirects to login when session is older than 90 days (absolute expiry)', async () => {
    const sessionId = 'old-session-id'
    const MAX_SESSION_AGE = 90 * 24 * 60 * 60
    await adapter.set(
      sessionId,
      {
        _type: 'session',
        accessToken: 'token',
        refreshToken: 'refresh',
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        createdAt: Math.floor(Date.now() / 1000) - (MAX_SESSION_AGE + 1), // 90 days + 1 second ago
        user: { sub: 'user-123' },
      },
      3600
    )

    const res = await app.request('/api/me', {
      headers: {
        Cookie: `__Host-session=${sessionId}`,
      },
    })

    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toBe('/auth/login')

    // Session should be deleted from store
    expect(await adapter.get(sessionId)).toBeNull()
  })

  it('redirects to custom login path when session is older than 90 days', async () => {
    const configWithCustomLogin = {
      issuer,
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      adapter,
      baseUrl: 'https://app.test.com',
      loginPath: '/custom/login',
    }
    const authCustomLogin = createBezzie(configWithCustomLogin)
    const appCustomLogin = new Hono()
    appCustomLogin.use('/api/*', authCustomLogin.middleware())

    const sessionId = 'old-session-id'
    const MAX_SESSION_AGE = 90 * 24 * 60 * 60
    await adapter.set(
      sessionId,
      {
        _type: 'session',
        accessToken: 'token',
        refreshToken: 'refresh',
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        createdAt: Math.floor(Date.now() / 1000) - (MAX_SESSION_AGE + 1),
        user: { sub: 'user-123' },
      },
      3600
    )

    const res = await appCustomLogin.request('/api/me', {
      headers: {
        Cookie: `__Host-session=${sessionId}`,
      },
    })

    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toBe('/custom/login')
  })

  describe('optionalMiddleware', () => {
    it('passes through with no cookie and no context set', async () => {
      app = new Hono<{ Variables: Variables }>()
      app.use('/api/*', auth.optionalMiddleware())
      app.get('/api/me', (c) =>
        c.json({
          user: c.get('user') ?? null,
          accessToken: c.get('accessToken') ?? null,
        })
      )

      const res = await app.request('/api/me')
      expect(res.status).toBe(200)
      const data = (await res.json()) as { user?: Record<string, unknown>; accessToken?: string }
      expect(data.user).toBeNull()
      expect(data.accessToken).toBeNull()
    })

    it('sets context for valid session', async () => {
      app = new Hono<{ Variables: Variables }>()
      app.use('/api/*', auth.optionalMiddleware())
      app.get('/api/me', (c) =>
        c.json({
          user: c.get('user') ?? null,
          accessToken: c.get('accessToken') ?? null,
        })
      )

      const sessionId = 'test-session-id'
      const user = { sub: 'user-123' }
      await adapter.set(
        sessionId,
        {
          _type: 'session',
          accessToken: 'valid-token',
          refreshToken: 'valid-refresh',
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
          createdAt: Math.floor(Date.now() / 1000),
          user,
        },
        3600
      )

      vi.mocked(oauth.validateJwtAccessToken).mockResolvedValue({} as oauth.JWTAccessTokenClaims)

      const res = await app.request('/api/me', {
        headers: {
          Cookie: `__Host-session=${sessionId}`,
        },
      })

      expect(res.status).toBe(200)
      const data = (await res.json()) as { user?: Record<string, unknown>; accessToken?: string }
      expect(data.user).toEqual(user)
      expect(data.accessToken).toBe('valid-token')
    })

    it('passes through but sets no context if session is invalid', async () => {
      app = new Hono<{ Variables: Variables }>()
      app.use('/api/*', auth.optionalMiddleware())
      app.get('/api/me', (c) =>
        c.json({
          user: c.get('user') ?? null,
          accessToken: c.get('accessToken') ?? null,
        })
      )

      const res = await app.request('/api/me', {
        headers: {
          Cookie: '__Host-session=non-existent',
        },
      })
      expect(res.status).toBe(200)
      const data = (await res.json()) as { user?: Record<string, unknown>; accessToken?: string }
      expect(data.user).toBeNull()
      expect(data.accessToken).toBeNull()
    })

    it('passes through but sets no context if session is expired and refresh fails', async () => {
      app = new Hono<{ Variables: Variables }>()
      app.use('/api/*', auth.optionalMiddleware())
      app.get('/api/me', (c) =>
        c.json({
          user: c.get('user') ?? null,
          accessToken: c.get('accessToken') ?? null,
        })
      )

      const sessionId = 'test-session-id'
      await adapter.set(
        sessionId,
        {
          _type: 'session',
          accessToken: 'expired-token',
          refreshToken: 'invalid-refresh',
          expiresAt: Math.floor(Date.now() / 1000) - 10,
          createdAt: Math.floor(Date.now() / 1000) - 1000,
          user: { sub: '123' },
        },
        3600
      )

      vi.mocked(oauth.refreshTokenGrantRequest).mockResolvedValue({} as Response)
      vi.mocked(oauth.processRefreshTokenResponse).mockRejectedValue(new Error('failed'))

      const res = await app.request('/api/me', {
        headers: {
          Cookie: `__Host-session=${sessionId}`,
        },
      })

      expect(res.status).toBe(200)
      const data = (await res.json()) as { user?: Record<string, unknown>; accessToken?: string }
      expect(data.user).toBeNull()
      expect(data.accessToken).toBeNull()
      expect(await adapter.get(sessionId)).toBeNull()
    })
  })
})
