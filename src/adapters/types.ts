import { Session } from '../session'

/**
 * Temporary state for the PKCE OAuth flow.
 */
export interface PKCEState {
  /**
   * Internal type discriminant.
   */
  _type: 'pkce'
  /**
   * Code verifier for PKCE.
   */
  codeVerifier: string
  /**
   * URL to redirect to after successful authentication.
   */
  returnTo?: string
  /**
   * CSRF token bound to the user's browser session via the `__Host-pkce-csrf` cookie.
   * Used to prevent login-CSRF attacks (S4).
   */
  csrfToken: string
  /**
   * OIDC `nonce` value. Generated at `/login`, passed in the authorization
   * request, and verified against the `nonce` claim of the returned ID token
   * at `/callback` to prevent ID token replay attacks (S8).
   */
  nonce: string
}

/**
 * A rate-limit counter for a single bucket and window, stored through the
 * same {@link SessionAdapter} used for sessions and PKCE state — see
 * `ratelimit.ts` for why counters reuse this store rather than needing a
 * separate one.
 */
export interface RateLimitRecord {
  /**
   * Internal type discriminant.
   */
  _type: 'ratelimit'
  /**
   * Number of requests counted in this window so far.
   */
  count: number
  /**
   * Start of the counting window, as epoch milliseconds.
   */
  windowStart: number
}

/**
 * Interface for session storage adapters.
 *
 * `get`/`set` also carry {@link RateLimitRecord} alongside sessions and PKCE
 * state. This is a source-compatible widening for the three built-in
 * adapters (they pass values through without branching on `_type`), and for
 * any custom adapter written against this interface: `set` accepting a wider
 * union is always safe for an implementor, and `get` returning a wider union
 * only matters to callers that switch on `_type` — see `ratelimit.ts` and
 * `middleware.ts` for where that narrowing happens.
 */
export interface SessionAdapter<TUser extends Record<string, unknown> = Record<string, unknown>> {
  /**
   * Retrieves a session, PKCE state, or rate-limit record by key.
   *
   * @param key Session ID, PKCE state key, or rate-limit bucket key
   * @returns The stored record, or null if not found
   */
  get(key: string): Promise<Session<TUser> | PKCEState | RateLimitRecord | null>

  /**
   * Stores a session, PKCE state, or rate-limit record.
   *
   * @param key Session ID, PKCE state key, or rate-limit bucket key
   * @param value Session, PKCE state, or rate-limit record
   * @param ttlSeconds Time-to-live in seconds
   */
  set(key: string, value: Session<TUser> | PKCEState | RateLimitRecord, ttlSeconds: number): Promise<void>

  /**
   * Deletes a session, PKCE state, or rate-limit record.
   *
   * @param key Session ID, PKCE state key, or rate-limit bucket key
   */
  delete(key: string): Promise<void>
}

/**
 * Factory function that produces a {@link SessionAdapter} for a given `TUser`.
 *
 * Consumers construct adapters via the factory form (e.g. `memoryAdapter()`,
 * `cloudflareKVAdapter(env.SESSION_KV)`) so `TUser` is inferred from
 * `createBezzie<TUser>(...)` rather than needing to be specified twice.
 */
export type SessionAdapterFactory = <TUser extends Record<string, unknown> = Record<string, unknown>>() => SessionAdapter<TUser>
