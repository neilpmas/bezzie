import { Session } from '../session'
import { SessionAdapter } from './types'

export interface RedisClient {
  get(key: string): Promise<string | null>
  set(key: string, value: string, options?: { ex?: number }): Promise<unknown>
  del(key: string): Promise<unknown>
}

export class RedisAdapter implements SessionAdapter {
  constructor(private redis: RedisClient) {}

  async get(sessionId: string): Promise<Session | null> {
    const session = await this.redis.get(sessionId)
    if (!session) return null
    return JSON.parse(session) as Session
  }

  async set(sessionId: string, session: Session, ttlSeconds: number): Promise<void> {
    await this.redis.set(sessionId, JSON.stringify(session), { ex: ttlSeconds })
  }

  async delete(sessionId: string): Promise<void> {
    await this.redis.del(sessionId)
  }
}
