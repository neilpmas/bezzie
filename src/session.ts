/**
 * Represents a user session.
 */
export interface Session {
  /**
   * OAuth access token.
   */
  accessToken: string
  /**
   * OAuth refresh token.
   */
  refreshToken?: string
  /**
   * OAuth ID token.
   */
  idToken?: string
  /**
   * Expiration time of the access token as a Unix timestamp (seconds).
   */
  expiresAt: number
  /**
   * Creation time of the session as a Unix timestamp (seconds).
   */
  createdAt: number
  /**
   * User information from the ID token or userinfo endpoint.
   */
  user: {
    /**
     * Unique identifier for the user.
     */
    sub: string
    /**
     * User's email address.
     */
    email?: string
    [key: string]: unknown
  }
}

export * from './adapters'
