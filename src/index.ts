import { Hono, type MiddlewareHandler } from 'hono'
import { authRoutes } from './routes'
import {
  middleware,
  optionalMiddleware,
  type AuthenticatedVariables,
  type OptionalVariables,
  type LoginHookContext,
  type RefreshHookContext,
  type LogoutHookContext,
  type HookErrorContext,
} from './middleware'
import { createDiscoveryCache, type DiscoveryCache } from './discovery'

import { CloudflareKVAdapter, type SessionAdapter } from './session'

/**
 * Configuration for Bezzie.
 */
export interface BezzieConfig<TUser extends Record<string, unknown> = Record<string, unknown>> {
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
   * Session adapter (e.g. `cloudflareKVAdapter(env.SESSION_KV)`).
   */
  adapter: SessionAdapter<TUser>

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
   * Hard overrides for specific provider values that cannot be derived from discovery.
   */
  providerOverrides?: {
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
   *
   * Providing a value **replaces** the default list entirely — it does not
   * extend it. If you set `scopes`, you must explicitly include every scope
   * you need.
   *
   * In particular, include `'offline_access'` if you want Bezzie to be able
   * to refresh access tokens; without it the provider will not issue a
   * refresh token and sessions will terminate when the access token expires.
   *
   * @default ['openid', 'profile', 'email', 'offline_access']
   * @example
   * // Good — includes offline_access for refresh support:
   * scopes: ['openid', 'profile', 'email', 'offline_access', 'read:things']
   *
   * // Bad — no refresh token will be issued:
   * scopes: ['openid', 'read:things']
   */
  scopes?: string[]

  /**
   * Buffer in seconds for refreshing the access token before it expires.
   * @default 60
   */
  refreshBufferSeconds?: number

  /**
   * Called at the end of /callback after the session is created.
   * Awaited. If it throws, the login is aborted and the partial session is deleted.
   * Use c.executionCtx?.waitUntil() for non-critical background work.
   */
  onLogin?: (ctx: LoginHookContext<TUser>) => Promise<void> | void

  /**
   * Called in middleware after a successful token refresh.
   * Awaited, but errors are caught and routed to onError — the request continues.
   */
  onRefresh?: (ctx: RefreshHookContext<TUser>) => Promise<void> | void

  /**
   * Called at /logout after the session is deleted.
   * Awaited, but errors are caught and routed to onError — logout always succeeds.
   */
  onLogout?: (ctx: LogoutHookContext<TUser>) => Promise<void> | void

  /**
   * Called when a non-fatal hook throws (onRefresh, onLogout).
   * Defaults to console.error. onLogin errors still bubble.
   */
  onError?: (err: unknown, ctx: HookErrorContext) => void
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
    providerOverrides: {
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
function cloudflareKVAdapter<TUser extends Record<string, unknown> = Record<string, unknown>>(
  kv: KVNamespace
): SessionAdapter<TUser> {
  return new CloudflareKVAdapter<TUser>(kv)
}

/**
 * The main Bezzie interface.
 */
export interface Bezzie<TUser extends Record<string, unknown> = Record<string, unknown>> {
  /**
   * Returns a Hono app containing the auth routes (/login, /callback, /logout).
   */
  routes: () => Hono

  /**
   * Returns a Hono middleware that protects routes and manages sessions.
   */
  middleware: () => MiddlewareHandler<{ Variables: AuthenticatedVariables<TUser> }>

  /**
   * Returns a Hono middleware that sets user context if a session exists but always calls next().
   */
  optionalMiddleware: () => MiddlewareHandler<{ Variables: OptionalVariables<TUser> }>
}

/**
 * Creates a new Bezzie instance.
 *
 * @param config Bezzie configuration
 * @returns Bezzie instance
 * @throws {Error} if required configuration is missing or invalid
 */
function createBezzie<TUser extends Record<string, unknown> = Record<string, unknown>>(
  config: BezzieConfig<TUser>
): Bezzie<TUser> {
  const required = ['issuer', 'clientId', 'clientSecret', 'adapter', 'baseUrl']
  for (const key of required) {
    if (!config[key as keyof BezzieConfig<TUser>]) {
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
  } as Bezzie<TUser> & { cache: DiscoveryCache }
}

export { createBezzie, cloudflareKVAdapter, middleware, optionalMiddleware }
export type {
  Variables,
  AuthenticatedVariables,
  OptionalVariables,
  LoginHookContext,
  RefreshHookContext,
  LogoutHookContext,
  HookErrorContext,
} from './middleware'
export type { SessionAdapter, PKCEState, Session, StoredSession } from './session'
export { CloudflareKVAdapter, RedisAdapter, MemoryAdapter } from './session'
