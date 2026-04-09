import { describe, it, expect, vi, beforeEach } from 'vitest'
import { getAuthorizationServer, createDiscoveryCache } from '../src/discovery'
import * as oauth from 'oauth4webapi'
import type { BezzieConfig } from '../src'
import { MemoryAdapter } from '../src'

vi.mock('oauth4webapi', async () => {
  const actual = await vi.importActual('oauth4webapi')
  return {
    ...actual,
    discoveryRequest: vi.fn(),
    processDiscoveryResponse: vi.fn(),
  }
})

describe('Discovery', () => {
  const issuer = 'https://test.auth0.com'
  const config: BezzieConfig = {
    issuer,
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    adapter: new MemoryAdapter(),
    baseUrl: 'https://app.test.com',
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('throws a custom error if discoveryRequest fails', async () => {
    const cache = createDiscoveryCache()
    vi.mocked(oauth.discoveryRequest).mockRejectedValue(new Error('Network error'))

    await expect(getAuthorizationServer(config, cache)).rejects.toThrow(
      `Bezzie: OIDC discovery failed for ${issuer}: Network error`
    )
  })

  it('throws a custom error if processDiscoveryResponse fails', async () => {
    const cache = createDiscoveryCache()
    vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockRejectedValue(new Error('Invalid metadata'))

    await expect(getAuthorizationServer(config, cache)).rejects.toThrow(
      `Bezzie: OIDC discovery failed for ${issuer}: Invalid metadata`
    )
  })

  it('handles non-Error objects in catch block', async () => {
    const cache = createDiscoveryCache()
    vi.mocked(oauth.discoveryRequest).mockRejectedValue('something went wrong')

    await expect(getAuthorizationServer(config, cache)).rejects.toThrow(
      `Bezzie: OIDC discovery failed for ${issuer}: something went wrong`
    )
  })
})
