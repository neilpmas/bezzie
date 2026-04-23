import { Session } from '../session'
import { SessionAdapter, SessionAdapterFactory, PKCEState } from './types'

interface MemorySession<TUser extends Record<string, unknown> = Record<string, unknown>> {
  session: Session<TUser> | PKCEState
  expiresAt: number
}

export class MemoryAdapter<TUser extends Record<string, unknown> = Record<string, unknown>>
  implements SessionAdapter<TUser>
{
  private store = new Map<string, MemorySession<TUser>>()
  private lastCleanup = 0
  private static readonly CLEANUP_INTERVAL_MS = 60_000

  /**
   * Evicts all entries whose TTL has expired.
   *
   * Workers runtimes don't support long-lived timers (`setInterval`), so rather
   * than scheduling cleanup we trigger it opportunistically from `get()` at
   * most once every `CLEANUP_INTERVAL_MS`. This bounds memory growth for
   * long-running processes (e.g. local dev, tests) without adding overhead to
   * every read.
   */
  cleanup(): void {
    const now = Date.now()
    for (const [id, entry] of this.store) {
      if (now > entry.expiresAt) {
        this.store.delete(id)
      }
    }
    this.lastCleanup = now
  }

  async get(sessionId: string): Promise<Session<TUser> | PKCEState | null> {
    // Proactive TTL eviction (C6): run at most once per CLEANUP_INTERVAL_MS.
    const now = Date.now()
    if (now - this.lastCleanup > MemoryAdapter.CLEANUP_INTERVAL_MS) {
      this.cleanup()
    }

    const entry = this.store.get(sessionId)
    if (!entry) return null
    if (now > entry.expiresAt) {
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

/**
 * Creates an in-memory session adapter factory. Useful for tests and local dev.
 */
export function memoryAdapter(): SessionAdapterFactory {
  return <TUser extends Record<string, unknown> = Record<string, unknown>>(): SessionAdapter<TUser> =>
    new MemoryAdapter<TUser>()
}
