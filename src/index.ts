import { Hono, type MiddlewareHandler } from 'hono'
import { authRoutes } from './routes'
import { middleware, optionalMiddleware, type Variables } from './middleware'
import { createDiscoveryCache, type DiscoveryCache } from './discovery'

import { CloudflareKVAdapter, type SessionAdapter } from './session'

/**
 * Configuration for Bezzie.
 */
export interface BezzieConfig {
  /**
   * Your OIDC provider issuer URL (e.g. `https://tenant.auth0.com`).
   */
  issuer: string

  /**
   * OAuth client ID.
   */
  clientId: string

  /**
   * OAuth client secret — keep this in Workers secrets.
   */
  clientSecret: string

  /**
   * Optional API audience identifier.
   */
  audience?: string

  /**
   * Session adapter (e.g. `cloudflareKV(env.SESSION_KV)`).
   */
  adapter: SessionAdapter

  /**
   * Base URL of your application (used for callback and redirects).
   */
  baseUrl: string

  /**
   * Optional path to the login route (defaults to /auth/login).
   */
  loginPath?: string

  /**
   * Whether to validate the access token (defaults to true).
   */
  validateAccessToken?: boolean

  /**
   * Optional tweaks for specific providers.
   */
  providerHints?: {
    /**
     * Custom logout URL if different from the default OIDC logout.
     */
    logoutUrl?: string

    /**
     * Custom token endpoint if different from the discovery metadata.
     */
    tokenEndpoint?: string
  }

  /**
   * Session TTL in seconds.
   * @default 60 * 60 * 24 * 30 (30 days)
   */
  sessionTtlSeconds?: number

  /**
   * PKCE state TTL in seconds.
   * @default 60 * 10 (10 minutes)
   */
  pkceStateTtlSeconds?: number

  /**
   * Session cookie name.
   * @default '__Host-session'
   */
  cookieName?: string

  /**
   * OAuth scopes to request.
   * @default ['openid', 'profile', 'email', 'offline_access']
   */
  scopes?: string[]

  /**
   * Buffer in seconds for refreshing the access token before it expires.
   * @default 60
   */
  refreshBufferSeconds?: number
}

/**
 * Common OIDC provider configurations.
 */
export const providers = {
  /**
   * Auth0 provider configuration.
   */
  auth0: (domain: string) => ({
    issuer: `https://${domain}`,
    providerHints: {
      logoutUrl: `https://${domain}/v2/logout`,
    },
  }),

  /**
   * Okta provider configuration.
   */
  okta: (domain: string) => ({
    issuer: `https://${domain}/oauth2/default`,
  }),

  /**
   * Keycloak provider configuration.
   */
  keycloak: (baseUrl: string, realm: string) => ({
    issuer: `${baseUrl}/realms/${realm}`,
  }),

  /**
   * Google provider configuration.
   */
  google: () => ({
    issuer: 'https://accounts.google.com',
  }),
}

/**
 * Creates a Cloudflare KV session adapter.
 */
function cloudflareKV(kv: KVNamespace): SessionAdapter {
  return new CloudflareKVAdapter(kv)
}

/**
 * The main Bezzie interface.
 */
export interface Bezzie {
  /**
   * Returns a Hono app containing the auth routes (/login, /callback, /logout).
   */
  routes: () => Hono

  /**
   * Returns a Hono middleware that protects routes and manages sessions.
   */
  middleware: () => MiddlewareHandler<{ Variables: Variables }>

  /**
   * Returns a Hono middleware that sets user context if a session exists but always calls next().
   */
  optionalMiddleware: () => MiddlewareHandler<{ Variables: Variables }>

  /**
   * Internal discovery cache.
   * @internal
   */
  cache: DiscoveryCache
}

/**
 * Creates a new Bezzie instance.
 *
 * @param config Bezzie configuration
 * @returns Bezzie instance
 * @throws {Error} if required configuration is missing or invalid
 */
function createBezzie(config: BezzieConfig): Bezzie {
  const required = ['issuer', 'clientId', 'clientSecret', 'adapter', 'baseUrl']
  for (const key of required) {
    if (!config[key as keyof BezzieConfig]) {
      throw new Error(`Bezzie: missing required config: ${key}`)
    }
  }

  if (!config.issuer.startsWith('https://')) {
    throw new Error('Bezzie: issuer must start with https://')
  }

  try {
    new URL(config.issuer)
  } catch {
    throw new Error('Bezzie: issuer must be a valid URL')
  }

  const cache = createDiscoveryCache()
  const router = authRoutes(config, cache)

  return {
    routes: () => router,
    middleware: () => middleware(config, cache),
    optionalMiddleware: () => optionalMiddleware(config, cache),
    cache,
  }
}

export { createBezzie, cloudflareKV, middleware, optionalMiddleware }
export type { Variables } from './middleware'
export type { SessionAdapter, PKCEState, Session } from './session'
export { CloudflareKVAdapter, RedisAdapter, MemoryAdapter } from './session'
