import { Session } from '../session'

export interface PKCEState {
  codeVerifier: string
  returnTo?: string
}

export interface SessionAdapter {
  get(sessionId: string): Promise<Session | PKCEState | null>
  set(sessionId: string, session: Session | PKCEState, ttlSeconds: number): Promise<void>
  delete(sessionId: string): Promise<void>
}
