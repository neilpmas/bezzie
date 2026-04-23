import { Session } from '../session'
import { SessionAdapter, SessionAdapterFactory, PKCEState } from './types'

export interface RedisClient {
  get(key: string): Promise<string | null>
  set(key: string, value: string, options?: { ex?: number }): Promise<unknown>
  del(key: string): Promise<unknown>
}

export class RedisAdapter<TUser extends Record<string, unknown> = Record<string, unknown>>
  implements SessionAdapter<TUser>
{
  constructor(private redis: RedisClient) {}

  async get(sessionId: string): Promise<Session<TUser> | PKCEState | null> {
    const session = await this.redis.get(sessionId)
    if (!session) return null
    return JSON.parse(session) as Session<TUser> | PKCEState
  }

  async set(
    sessionId: string,
    session: Session<TUser> | PKCEState,
    ttlSeconds: number
  ): Promise<void> {
    await this.redis.set(sessionId, JSON.stringify(session), { ex: ttlSeconds })
  }

  async delete(sessionId: string): Promise<void> {
    await this.redis.del(sessionId)
  }
}

/**
 * Creates a Redis-backed session adapter factory.
 */
export function redisAdapter(client: RedisClient): SessionAdapterFactory {
  return <TUser extends Record<string, unknown> = Record<string, unknown>>(): SessionAdapter<TUser> =>
    new RedisAdapter<TUser>(client)
}
