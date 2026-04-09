import { describe, it, expect, vi } from 'vitest'
import { createBezzie, MemoryAdapter, type PKCEState, type Session } from '../src'
import * as oauth from 'oauth4webapi'

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

describe('OAuth Routes', () => {
  const adapter = new MemoryAdapter()
  const config = {
    issuer: 'https://test.auth0.com',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    audience: 'https://api.test.com',
    adapter,
    baseUrl: 'https://app.test.com',
  }

  const auth = createBezzie(config)
  const app = auth.routes()

  describe('GET /login', () => {
    it('redirects to the provider authorization URL', async () => {
      auth.cache.cachedAS = null
      auth.cache.cacheExpiresAt = 0
      const mockAs = { 
        issuer: config.issuer,
        authorization_endpoint: `${config.issuer}/authorize`
      }
      vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)

      const res = await app.request('/login')
      expect(res.status).toBe(302)
      const location = res.headers.get('Location')
      expect(location).toContain(`${config.issuer}/authorize`)
      expect(location).toContain(`client_id=${config.clientId}`)
      expect(location).toContain('response_type=code')
      expect(location).toContain(`redirect_uri=${encodeURIComponent(config.baseUrl + '/auth/callback')}`)
      expect(location).toContain('scope=openid+profile+email+offline_access')
      expect(location).toContain('code_challenge=')
      expect(location).toContain('code_challenge_method=S256')
      expect(location).toContain(`audience=${encodeURIComponent(config.audience)}`)
    })

    it('stores PKCE state in adapter', async () => {
      auth.cache.cachedAS = null
      auth.cache.cacheExpiresAt = 0
      const mockAs = { 
        issuer: config.issuer,
        authorization_endpoint: `${config.issuer}/authorize`
      }
      vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)

      const res = await app.request('/login')
      const location = new URL(res.headers.get('Location')!)
      const state = location.searchParams.get('state')

      const stored = await adapter.get(`pkce:${state}`) as PKCEState
      expect(stored).toBeDefined()
      expect(typeof stored.codeVerifier).toBe('string')
    })

    it('stores returnTo in PKCE state if provided', async () => {
      auth.cache.cachedAS = null
      auth.cache.cacheExpiresAt = 0
      const mockAs = { 
        issuer: config.issuer,
        authorization_endpoint: `${config.issuer}/authorize`
      }
      vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)

      const res = await app.request('/login?returnTo=/dashboard')
      const location = new URL(res.headers.get('Location')!)
      const state = location.searchParams.get('state')

      const stored = await adapter.get(`pkce:${state}`) as PKCEState
      expect(stored.returnTo).toBe('/dashboard')
    })
  })

  describe('GET /callback', () => {
    it('returns 400 with error parameter', async () => {
      const res1 = await app.request('/callback?error=access_denied')
      expect(res1.status).toBe(400)
      expect(await res1.text()).toBe('Access was denied.')

      const res2 = await app.request('/callback?error=server_error')
      expect(res2.status).toBe(400)
      expect(await res2.text()).toBe('The provider returned a server error.')

      const res3 = await app.request('/callback?error=temporarily_unavailable')
      expect(res3.status).toBe(400)
      expect(await res3.text()).toBe('The provider is temporarily unavailable. Please try again.')

      const res4 = await app.request('/callback?error=unknown')
      expect(res4.status).toBe(400)
      expect(await res4.text()).toBe('Authentication failed.')
    })

    it('returns 400 with invalid state', async () => {
      const res = await app.request('/callback?state=invalid&code=123')
      expect(res.status).toBe(400)
      expect(await res.text()).toBe('Invalid or expired state')
    })

    it('with valid state exchanges code, stores session, sets cookie, redirects', async () => {
      const state = 'test-state'
      const code = 'test-code'
      const codeVerifier = 'test-verifier'
      
      await adapter.set(`pkce:${state}`, { codeVerifier } as PKCEState, 600)

      // Setup mocks
      const mockAs = { issuer: config.issuer }
      vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)
      vi.mocked(oauth.authorizationCodeGrantRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processAuthorizationCodeResponse).mockResolvedValue({
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token',
        expires_in: 3600,
        id_token: 'mock-id-token',
      } as oauth.TokenEndpointResponse)
      vi.mocked(oauth.getValidatedIdTokenClaims).mockReturnValue({
        sub: 'user-123',
        email: 'user@example.com',
      } as unknown as oauth.IDToken)

      const res = await app.request(`/callback?state=${state}&code=${code}`)

      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toBe('/')
      
      // Check cookie
      const cookie = res.headers.get('Set-Cookie')
      expect(cookie).toContain('__Host-session=')
      expect(cookie).toContain('HttpOnly')
      expect(cookie).toContain('Secure')
      expect(cookie).toContain('SameSite=Strict')
      expect(cookie).toContain('Max-Age=2592000')

      // Check session in adapter
      const sessionId = cookie!.match(/__Host-session=([^;]+)/)![1]
      const session = await adapter.get(sessionId) as Session
      expect(session).toBeDefined()
      expect(session!.accessToken).toBe('mock-access-token')
      expect(session!.idToken).toBe('mock-id-token')
      expect(session!.user.sub).toBe('user-123')
      expect(session!.createdAt).toBeTypeOf('number')
      expect(session!.createdAt).toBeLessThanOrEqual(Math.floor(Date.now() / 1000))

      expect(await adapter.get(`pkce:${state}`)).toBeNull()
    })

    it('redirects to returnTo after successful login', async () => {
      const state = 'test-state-ret'
      const code = 'test-code'
      const codeVerifier = 'test-verifier'
      const returnTo = '/dashboard'
      
      await adapter.set(`pkce:${state}`, { codeVerifier, returnTo } as PKCEState, 600)

      // Setup mocks
      const mockAs = { issuer: config.issuer }
      vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)
      vi.mocked(oauth.authorizationCodeGrantRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processAuthorizationCodeResponse).mockResolvedValue({
        access_token: 'mock-access-token',
        expires_in: 3600,
        id_token: 'mock-id-token',
      } as oauth.TokenEndpointResponse)
      vi.mocked(oauth.getValidatedIdTokenClaims).mockReturnValue({
        sub: 'user-123',
      } as unknown as oauth.IDToken)

      const res = await app.request(`/callback?state=${state}&code=${code}`)

      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toBe('/dashboard')
    })

    it('rejects external returnTo and falls back to /', async () => {
      const state = 'test-state-evil'
      const code = 'test-code'
      const codeVerifier = 'test-verifier'
      const returnTo = 'https://evil.com/malicious'
      
      await adapter.set(`pkce:${state}`, { codeVerifier, returnTo } as PKCEState, 600)

      const res = await app.request(`/callback?state=${state}&code=${code}`)

      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toBe('/')
    })

    it('rejects protocol-relative returnTo (//) and falls back to /', async () => {
      const state = 'test-state-proto'
      const code = 'test-code'
      const codeVerifier = 'test-verifier'
      const returnTo = '//evil.com'
      
      await adapter.set(`pkce:${state}`, { codeVerifier, returnTo } as PKCEState, 600)

      const res = await app.request(`/callback?state=${state}&code=${code}`)

      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toBe('/')
    })
  })

  describe('POST /logout', () => {
    it('redirects to / if no logout URL can be determined', async () => {
      auth.cache.cachedAS = null
      auth.cache.cacheExpiresAt = 0
      const mockAs = { issuer: config.issuer }
      vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)

      const res = await app.request('/logout', { method: 'POST' })
      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toBe('/')
    })

    it('uses providerHints.logoutUrl if provided', async () => {
      const customConfig = { ...config, providerHints: { logoutUrl: 'https://test.auth0.com/v2/logout' } }
      const customAuth = createBezzie(customConfig)
      const customApp = customAuth.routes()

      const mockAs = { issuer: customConfig.issuer }
      vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)

      const res = await customApp.request('/logout', { method: 'POST' })

      expect(res.status).toBe(302)
      const location = res.headers.get('Location')
      expect(location).toContain('https://test.auth0.com/v2/logout')
      expect(location).toContain(`client_id=${customConfig.clientId}`)
      expect(location).toContain(`returnTo=${encodeURIComponent(customConfig.baseUrl)}`)
    })

    it('redirects to OIDC end_session_endpoint if available', async () => {
      auth.cache.cachedAS = null
      auth.cache.cacheExpiresAt = 0

      const mockAs = { 
        issuer: config.issuer,
        end_session_endpoint: `${config.issuer}/oidc/logout`
      }
      vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)

      const res = await app.request('/logout', { method: 'POST' })

      expect(res.status).toBe(302)
      const location = res.headers.get('Location')
      expect(location).toContain(`${config.issuer}/oidc/logout`)
      expect(location).toContain(`client_id=${config.clientId}`)
      expect(location).toContain(`post_logout_redirect_uri=${encodeURIComponent(config.baseUrl)}`)
    })

    it('with valid session cookie - deletes session from adapter, clears cookie, and adds id_token_hint', async () => {
      auth.cache.cachedAS = null
      auth.cache.cacheExpiresAt = 0
      const sessionId = 'test-session-id'
      const idToken = 'mock-id-token'
      await adapter.set(sessionId, { 
        accessToken: 'test',
        refreshToken: 'refresh',
        idToken,
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        createdAt: Math.floor(Date.now() / 1000),
        user: { sub: 'user-123' },
      } as Session, 3600)

      const mockAs = { 
        issuer: config.issuer,
        end_session_endpoint: `${config.issuer}/logout`
      }
      vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)

      const res = await app.request('/logout', {
        method: 'POST',
        headers: {
          Cookie: `__Host-session=${sessionId}`,
        },
      })

      expect(res.status).toBe(302)
      const location = res.headers.get('Location')
      expect(location).toContain(`id_token_hint=${idToken}`)

      // Check cookie cleared
      const setCookieHeader = res.headers.get('Set-Cookie')
      expect(setCookieHeader).toContain('__Host-session=;')
      expect(setCookieHeader).toContain('Max-Age=0')
      expect(setCookieHeader).toContain('HttpOnly')
      expect(setCookieHeader).toContain('Secure')
      expect(setCookieHeader).toContain('SameSite=Strict')

      // Check session deleted from adapter
      expect(await adapter.get(sessionId)).toBeNull()
    })
    it('uses providerHints.logoutUrl and adds id_token_hint if session present', async () => {
      const customConfig = { ...config, providerHints: { logoutUrl: 'https://test.auth0.com/v2/logout' } }
      const customAuth = createBezzie(customConfig)
      const customApp = customAuth.routes()

      const sessionId = 'test-session-id'
      const idToken = 'mock-id-token'
      await adapter.set(sessionId, { 
        accessToken: 'test',
        idToken,
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        createdAt: Math.floor(Date.now() / 1000),
        user: { sub: 'user-123' },
      } as Session, 3600)

      const mockAs = { issuer: customConfig.issuer }
      vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)

      const res = await customApp.request('/logout', { 
        method: 'POST',
        headers: {
          Cookie: `__Host-session=${sessionId}`,
        },
      })

      expect(res.status).toBe(302)
      const location = res.headers.get('Location')
      expect(location).toContain('https://test.auth0.com/v2/logout')
      expect(location).toContain(`client_id=${customConfig.clientId}`)
      expect(location).toContain(`id_token_hint=${idToken}`)
    })
  })
})
