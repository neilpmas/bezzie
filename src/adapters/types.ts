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
 * Interface for session storage adapters.
 */
export interface SessionAdapter<TUser extends Record<string, unknown> = Record<string, unknown>> {
  /**
   * Retrieves a session or PKCE state by ID.
   *
   * @param sessionId Session ID
   * @returns Session, PKCE state, or null if not found
   */
  get(sessionId: string): Promise<Session<TUser> | PKCEState | null>

  /**
   * Stores a session or PKCE state.
   *
   * @param sessionId Session ID
   * @param session Session or PKCE state
   * @param ttlSeconds Time-to-live in seconds
   */
  set(sessionId: string, session: Session<TUser> | PKCEState, ttlSeconds: number): Promise<void>

  /**
   * Deletes a session or PKCE state.
   *
   * @param sessionId Session ID
   */
  delete(sessionId: string): Promise<void>
}

/**
 * Factory function that produces a {@link SessionAdapter} for a given `TUser`.
 *
 * Consumers construct adapters via the factory form (e.g. `memoryAdapter()`,
 * `cloudflareKVAdapter(env.SESSION_KV)`) so `TUser` is inferred from
 * `createBezzie<TUser>(...)` rather than needing to be specified twice.
 */
export type SessionAdapterFactory = <TUser extends Record<string, unknown> = Record<string, unknown>>() => SessionAdapter<TUser>
