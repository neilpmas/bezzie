import { Session } from '../session'

/**
 * Temporary state for the PKCE OAuth flow.
 */
export interface PKCEState {
  /**
   * Code verifier for PKCE.
   */
  codeVerifier: string
  /**
   * URL to redirect to after successful authentication.
   */
  returnTo?: string
}

/**
 * Interface for session storage adapters.
 */
export interface SessionAdapter {
  /**
   * Retrieves a session or PKCE state by ID.
   *
   * @param sessionId Session ID
   * @returns Session, PKCE state, or null if not found
   */
  get(sessionId: string): Promise<Session | PKCEState | null>

  /**
   * Stores a session or PKCE state.
   *
   * @param sessionId Session ID
   * @param session Session or PKCE state
   * @param ttlSeconds Time-to-live in seconds
   */
  set(sessionId: string, session: Session | PKCEState, ttlSeconds: number): Promise<void>

  /**
   * Deletes a session or PKCE state.
   *
   * @param sessionId Session ID
   */
  delete(sessionId: string): Promise<void>
}
