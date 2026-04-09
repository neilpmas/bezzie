import * as oauth from 'oauth4webapi'
import type { BezzieConfig } from './index'

export interface DiscoveryCache {
  cachedAS: oauth.AuthorizationServer | null
  cacheExpiresAt: number
  jwksCache: oauth.JWKSCacheInput
}

export function createDiscoveryCache(): DiscoveryCache {
  return { cachedAS: null, cacheExpiresAt: 0, jwksCache: {} }
}

export async function getAuthorizationServer(
  config: BezzieConfig,
  cache: DiscoveryCache
): Promise<oauth.AuthorizationServer> {
  if (cache.cachedAS && Date.now() < cache.cacheExpiresAt) {
    return cache.cachedAS
  }
  const issuer = new URL(config.issuer)
  try {
    const response = await oauth.discoveryRequest(issuer)
    const as = await oauth.processDiscoveryResponse(issuer, response)
    const cachedAS = config.providerHints?.tokenEndpoint
      ? { ...as, token_endpoint: config.providerHints.tokenEndpoint }
      : as
    cache.cachedAS = cachedAS
    cache.cacheExpiresAt = Date.now() + 60 * 60 * 1000
    return cachedAS
  } catch (err) {
    throw new Error(
      `Bezzie: OIDC discovery failed for ${config.issuer}: ${err instanceof Error ? err.message : String(err)}`,
      { cause: err }
    )
  }
}
