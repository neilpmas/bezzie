import { Session } from '../session'
import { SessionAdapter, PKCEState } from './types'

interface MemorySession<TUser extends Record<string, unknown> = Record<string, unknown>> {
  session: Session<TUser> | PKCEState
  expiresAt: number
}

export class MemoryAdapter<TUser extends Record<string, unknown> = Record<string, unknown>>
  implements SessionAdapter<TUser>
{
  private store = new Map<string, MemorySession<TUser>>()

  async get(sessionId: string): Promise<Session<TUser> | PKCEState | null> {
    const entry = this.store.get(sessionId)
    if (!entry) return null
    if (Date.now() > entry.expiresAt) {
      this.store.delete(sessionId)
      return null
    }
    return entry.session
  }

  async set(
    sessionId: string,
    session: Session<TUser> | PKCEState,
    ttlSeconds: number
  ): Promise<void> {
    this.store.set(sessionId, {
      session,
      expiresAt: Date.now() + ttlSeconds * 1000,
    })
  }

  async delete(sessionId: string): Promise<void> {
    this.store.delete(sessionId)
  }
}
