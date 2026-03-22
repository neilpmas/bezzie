import { Session } from '../session'

export interface SessionAdapter {
  get(sessionId: string): Promise<Session | null>
  set(sessionId: string, session: Session, ttlSeconds: number): Promise<void>
  delete(sessionId: string): Promise<void>
}
