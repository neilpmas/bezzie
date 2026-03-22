import { Session } from '../session'
import { SessionAdapter, PKCEState } from './types'

export class CloudflareKVAdapter implements SessionAdapter {
  constructor(private kv: KVNamespace) {}

  async get(sessionId: string): Promise<Session | PKCEState | null> {
    const session = await this.kv.get<Session | PKCEState>(sessionId, 'json')
    return session
  }

  async set(sessionId: string, session: Session | PKCEState, ttlSeconds: number): Promise<void> {
    if (ttlSeconds < 60) {
      throw new Error('Bezzie: KV TTL must be at least 60 seconds')
    }
    await this.kv.put(sessionId, JSON.stringify(session), {
      expirationTtl: ttlSeconds,
    })
  }

  async delete(sessionId: string): Promise<void> {
    await this.kv.delete(sessionId)
  }
}
