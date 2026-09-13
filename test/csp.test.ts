import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createBezzie, MemoryAdapter } from '../src'
import type { DiscoveryCache } from '../src/discovery'
import * as oauth from 'oauth4webapi'

vi.mock('oauth4webapi', async () => {
  const actual = await vi.importActual('oauth4webapi')
  return {
    ...actual,
    discoveryRequest: vi.fn(),
    processDiscoveryResponse: vi.fn(),
  }
})

describe('cspContributions', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  function resetCache(auth: unknown) {
    ;(auth as unknown as { cache: DiscoveryCache }).cache.cachedAS = null
    ;(auth as unknown as { cache: DiscoveryCache }).cache.cacheExpiresAt = 0
  }

  it('returns the authorization and end_session origins under form-action, deduped', async () => {
    const auth = createBezzie({
      issuer: 'https://tenant.eu.auth0.com',
      clientId: 'id',
      clientSecret: 'secret',
      adapter: () => new MemoryAdapter(),
      baseUrl: 'https://app.test.com',
    })
    resetCache(auth)

    vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue({
      issuer: 'https://tenant.eu.auth0.com',
      authorization_endpoint: 'https://tenant.eu.auth0.com/authorize',
      end_session_endpoint: 'https://tenant.eu.auth0.com/v2/logout',
    } as oauth.AuthorizationServer)

    const contributions = await auth.cspContributions()

    // Same-origin Auth0 case — one entry, not two.
    expect(contributions['form-action']).toEqual(['https://tenant.eu.auth0.com'])
    expect(contributions['connect-src']).toEqual([])
    expect(contributions['frame-src']).toEqual([])
  })

  it('prefers providerOverrides.logoutUrl over end_session_endpoint', async () => {
    const auth = createBezzie({
      issuer: 'https://tenant.okta.com',
      clientId: 'id',
      clientSecret: 'secret',
      adapter: () => new MemoryAdapter(),
      baseUrl: 'https://app.test.com',
      providerOverrides: { logoutUrl: 'https://logout.example.com/end' },
    })
    resetCache(auth)

    vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue({
      issuer: 'https://tenant.okta.com',
      authorization_endpoint: 'https://tenant.okta.com/authorize',
      end_session_endpoint: 'https://tenant.okta.com/logout',
    } as oauth.AuthorizationServer)

    const contributions = await auth.cspContributions()

    expect(contributions['form-action']).toContain('https://tenant.okta.com')
    expect(contributions['form-action']).toContain('https://logout.example.com')
    expect(contributions['form-action']).not.toContain('https://tenant.okta.com/logout')
    expect(contributions['form-action']).toHaveLength(2)
  })

  it('reuses the discovery cache — no extra discovery request on a second call', async () => {
    const auth = createBezzie({
      issuer: 'https://tenant.auth0.com',
      clientId: 'id',
      clientSecret: 'secret',
      adapter: () => new MemoryAdapter(),
      baseUrl: 'https://app.test.com',
    })
    resetCache(auth)

    vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue({
      issuer: 'https://tenant.auth0.com',
      authorization_endpoint: 'https://tenant.auth0.com/authorize',
    } as oauth.AuthorizationServer)

    await auth.cspContributions()
    await auth.cspContributions()

    expect(oauth.discoveryRequest).toHaveBeenCalledTimes(1)
  })
})
