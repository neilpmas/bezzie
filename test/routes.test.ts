import { describe, it, expect, vi } from 'vitest'
import { env } from 'cloudflare:test'
import { createBezzie } from '../src/index'
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
  const config = {
    domain: 'test.auth0.com',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    audience: 'https://api.test.com',
    kv: env.SESSION_KV,
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
      expect(location).toContain('scope=openid+profile+email')
      expect(location).toContain('code_challenge=')
      expect(location).toContain('code_challenge_method=S256')
      expect(location).toContain(`audience=${encodeURIComponent(config.audience)}`)
    })

    it('stores PKCE state in KV', async () => {
      const res = await app.request('/login')
      const location = new URL(res.headers.get('Location')!)
      const state = location.searchParams.get('state')
      
      const storedVerifier = await env.SESSION_KV.get(`pkce:${state}`)
      expect(storedVerifier).toBeDefined()
      expect(typeof storedVerifier).toBe('string')
    })
  })

  describe('GET /callback', () => {
    it('returns 400 with invalid state', async () => {
      const res = await app.request('/callback?state=invalid&code=123')
      expect(res.status).toBe(400)
      expect(await res.text()).toBe('Invalid or expired state')
    })

    it('with valid state exchanges code, stores session, sets cookie, redirects', async () => {
      const state = 'test-state'
      const code = 'test-code'
      const codeVerifier = 'test-verifier'
      
      await env.SESSION_KV.put(`pkce:${state}`, codeVerifier)

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

      // Check session in KV
      const sessionId = cookie!.match(/sessionId=([^;]+)/)![1]
      const sessionJson = await env.SESSION_KV.get(sessionId)
      expect(sessionJson).toBeDefined()
      const session = JSON.parse(sessionJson!)
      expect(session.accessToken).toBe('mock-access-token')
      expect(session.user.sub).toBe('user-123')

      // Check PKCE state deleted
      expect(await env.SESSION_KV.get(`pkce:${state}`)).toBeNull()
    })
  })
})
