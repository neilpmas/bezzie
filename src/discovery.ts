import * as oauth from 'oauth4webapi'
import { DiscoveryError } from './errors'

/**
 * Minimal config shape that discovery needs — it only reads `issuer` and
 * `providerOverrides.tokenEndpoint`. Accepting this interface (rather than
 * `BezzieConfig`) avoids a generic parameter that has no bearing on discovery.
 */
interface DiscoveryConfig {
  issuer: string
  providerOverrides?: {
    tokenEndpoint?: string
  }
}

export interface DiscoveryCache {
  cachedAS: oauth.AuthorizationServer | null
  cacheExpiresAt: number
  jwksCache: oauth.JWKSCacheInput
}

export function createDiscoveryCache(): DiscoveryCache {
  return { cachedAS: null, cacheExpiresAt: 0, jwksCache: {} }
}

export async function getAuthorizationServer(
  config: DiscoveryConfig,
  cache: DiscoveryCache
): Promise<oauth.AuthorizationServer> {
  if (cache.cachedAS && Date.now() < cache.cacheExpiresAt) {
    return cache.cachedAS
  }
  const issuer = new URL(config.issuer)
  try {
    const response = await oauth.discoveryRequest(issuer, { signal: AbortSignal.timeout(5000) })
    const as = await oauth.processDiscoveryResponse(issuer, response)
    const cachedAS = config.providerOverrides?.tokenEndpoint
      ? { ...as, token_endpoint: config.providerOverrides.tokenEndpoint }
      : as
    cache.cachedAS = cachedAS
    cache.cacheExpiresAt = Date.now() + 60 * 60 * 1000
    return cachedAS
  } catch (err) {
    throw new DiscoveryError(
      `Bezzie: OIDC discovery failed for ${config.issuer}: ${err instanceof Error ? err.message : String(err)}`,
      { cause: err }
    )
  }
}
