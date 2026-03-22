import { describe, it, expect, vi } from 'vitest'
import { createBezzie, MemoryAdapter, type PKCEState, type Session } from '../src/index'
import { _resetDiscoveryCache } from '../src/routes'
import * as oauth from 'oauth4webapi'

// Mock oauth4webapi
vi.mock('oauth4webapi', async () => {
  const actual = await vi.importActual('oauth4webapi')
  return {
    ...actual,
    discoveryRequest: vi.fn(),
    processDiscoveryResponse: vi.fn(),
    authorizationCodeGrantRequest: vi.fn(),
    processAuthorizationCodeOpenIDResponse: vi.fn(),
    getValidatedIdTokenClaims: vi.fn(),
  }
})

describe('OAuth Routes', () => {
  const adapter = new MemoryAdapter()
  const config = {
    domain: 'test.auth0.com',
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
      const res = await app.request('/login')
      expect(res.status).toBe(302)
      const location = res.headers.get('Location')
      expect(location).toContain(`https://${config.domain}/authorize`)
      expect(location).toContain(`client_id=${config.clientId}`)
      expect(location).toContain('response_type=code')
      expect(location).toContain(`redirect_uri=${encodeURIComponent(config.baseUrl + '/auth/callback')}`)
      expect(location).toContain('scope=openid+profile+email+offline_access')
      expect(location).toContain('code_challenge=')
      expect(location).toContain('code_challenge_method=S256')
      expect(location).toContain(`audience=${encodeURIComponent(config.audience)}`)
    })

    it('stores PKCE state in adapter', async () => {
      const res = await app.request('/login')
      const location = new URL(res.headers.get('Location')!)
      const state = location.searchParams.get('state')

      const stored = await adapter.get(`pkce:${state}`) as PKCEState
      expect(stored).toBeDefined()
      expect(typeof stored.codeVerifier).toBe('string')
    })

    it('stores returnTo in PKCE state if provided', async () => {
      const res = await app.request('/login?returnTo=/dashboard')
      const location = new URL(res.headers.get('Location')!)
      const state = location.searchParams.get('state')

      const stored = await adapter.get(`pkce:${state}`) as PKCEState
      expect(stored.returnTo).toBe('/dashboard')
    })
  })

  describe('GET /callback', () => {
    it('returns 400 with error parameter', async () => {
      const res = await app.request('/callback?error=access_denied')
      expect(res.status).toBe(400)
      expect(await res.text()).toBe('OAuth error: access_denied')
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
      const mockAs = { issuer: `https://${config.domain}` }
      vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)
      vi.mocked(oauth.authorizationCodeGrantRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processAuthorizationCodeOpenIDResponse).mockResolvedValue({
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token',
        expires_in: 3600,
        id_token: 'mock-id-token',
      } as oauth.OpenIDTokenEndpointResponse)
      vi.mocked(oauth.getValidatedIdTokenClaims).mockReturnValue({
        sub: 'user-123',
        email: 'user@example.com',
      } as oauth.IDTokenClaims)

      const res = await app.request(`/callback?state=${state}&code=${code}`)

      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toBe('/')
      
      // Check cookie
      const cookie = res.headers.get('Set-Cookie')
      expect(cookie).toContain('sessionId=')
      expect(cookie).toContain('HttpOnly')
      expect(cookie).toContain('Secure')
      expect(cookie).toContain('SameSite=Strict')

      // Check session in adapter
      const sessionId = cookie!.match(/sessionId=([^;]+)/)![1]
      const session = await adapter.get(sessionId) as Session
      expect(session).toBeDefined()
      expect(session!.accessToken).toBe('mock-access-token')
      expect(session!.user.sub).toBe('user-123')

      expect(await adapter.get(`pkce:${state}`)).toBeNull()
    })

    it('redirects to returnTo after successful login', async () => {
      const state = 'test-state-ret'
      const code = 'test-code'
      const codeVerifier = 'test-verifier'
      const returnTo = '/dashboard'
      
      await adapter.set(`pkce:${state}`, { codeVerifier, returnTo } as PKCEState, 600)

      // Setup mocks
      const mockAs = { issuer: `https://${config.domain}` }
      vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)
      vi.mocked(oauth.authorizationCodeGrantRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processAuthorizationCodeOpenIDResponse).mockResolvedValue({
        access_token: 'mock-access-token',
        expires_in: 3600,
        id_token: 'mock-id-token',
      } as oauth.OpenIDTokenEndpointResponse)
      vi.mocked(oauth.getValidatedIdTokenClaims).mockReturnValue({
        sub: 'user-123',
      } as oauth.IDTokenClaims)

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

  describe('GET /logout', () => {
    it('with valid session cookie - deletes session from adapter, clears cookie, redirects to Auth0 logout if no end_session_endpoint', async () => {
      const sessionId = 'test-session-id'
      await adapter.set(sessionId, { accessToken: 'test' } as Session, 3600)

      const mockAs = { issuer: `https://${config.domain}` }
      vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)

      const res = await app.request('/logout', {
        headers: {
          Cookie: `sessionId=${sessionId}`,
        },
      })

      expect(res.status).toBe(302)
      const location = res.headers.get('Location')
      expect(location).toContain(`https://${config.domain}/v2/logout`)
      expect(location).toContain(`client_id=${config.clientId}`)
      expect(location).toContain(`returnTo=${encodeURIComponent(config.baseUrl)}`)

      // Check cookie cleared
      const setCookie = res.headers.get('Set-Cookie')
      expect(setCookie).toContain('sessionId=;')
      expect(setCookie).toContain('Max-Age=0')

      // Check session deleted from adapter
      expect(await adapter.get(sessionId)).toBeNull()
    })

    it('redirects to OIDC end_session_endpoint if available', async () => {
      _resetDiscoveryCache()

      const mockAs = { 
        issuer: `https://${config.domain}`,
        end_session_endpoint: `https://${config.domain}/oidc/logout`
      }
      vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)

      const res = await app.request('/logout')

      expect(res.status).toBe(302)
      const location = res.headers.get('Location')
      expect(location).toContain(`https://${config.domain}/oidc/logout`)
      expect(location).toContain(`client_id=${config.clientId}`)
      expect(location).toContain(`post_logout_redirect_uri=${encodeURIComponent(config.baseUrl)}`)
    })

    it('with no cookie - redirects cleanly', async () => {
      _resetDiscoveryCache()

      const mockAs = { issuer: `https://${config.domain}` }
      vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)

      const res = await app.request('/logout')

      expect(res.status).toBe(302)
      const location = res.headers.get('Location')
      expect(location).toContain(`https://${config.domain}/v2/logout`)
    })
  })
})
