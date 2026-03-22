import { Session } from '../session'
import { SessionAdapter, PKCEState } from './types'

interface MemorySession {
  session: Session | PKCEState
  expiresAt: number
}

export class MemoryAdapter implements SessionAdapter {
  private store = new Map<string, MemorySession>()

  async get(sessionId: string): Promise<Session | PKCEState | null> {
    const entry = this.store.get(sessionId)
    if (!entry) return null
    if (Date.now() > entry.expiresAt) {
      this.store.delete(sessionId)
      return null
    }
    return entry.session
  }

  async set(sessionId: string, session: Session | PKCEState, ttlSeconds: number): Promise<void> {
    this.store.set(sessionId, {
      session,
      expiresAt: Date.now() + ttlSeconds * 1000,
    })
  }

  async delete(sessionId: string): Promise<void> {
    this.store.delete(sessionId)
  }
}
