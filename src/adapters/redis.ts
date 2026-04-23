import { Session } from '../session'
import { SessionAdapter, SessionAdapterFactory, PKCEState } from './types'

export interface RedisClient {
  get(key: string): Promise<string | null>
  set(key: string, value: string, options?: { ex?: number }): Promise<unknown>
  del(key: string): Promise<unknown>
}

/**
 * Redis-backed session adapter.
 *
 * Compatible with any Redis client that implements the {@link RedisClient} interface,
 * including [Upstash Redis](https://upstash.com) — the recommended choice for Cloudflare Workers
 * because it communicates over HTTP rather than TCP.
 *
 * @example
 * ```typescript
 * import { redisAdapter } from 'bezzie'
 * import { Redis } from '@upstash/redis/cloudflare'
 *
 * adapter: redisAdapter(new Redis({
 *   url: env.UPSTASH_REDIS_REST_URL,
 *   token: env.UPSTASH_REDIS_REST_TOKEN,
 * }))
 * ```
 */
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
 *
 * Accepts any client that satisfies the {@link RedisClient} interface, including
 * [Upstash Redis](https://upstash.com) (`@upstash/redis/cloudflare`) — recommended for
 * Cloudflare Workers because it uses the Upstash REST API over HTTP rather than a TCP socket.
 *
 * @example
 * ```typescript
 * import { redisAdapter } from 'bezzie'
 * import { Redis } from '@upstash/redis/cloudflare'
 *
 * adapter: redisAdapter(new Redis({
 *   url: env.UPSTASH_REDIS_REST_URL,
 *   token: env.UPSTASH_REDIS_REST_TOKEN,
 * }))
 * ```
 */
export function redisAdapter(client: RedisClient): SessionAdapterFactory {
  return <TUser extends Record<string, unknown> = Record<string, unknown>>(): SessionAdapter<TUser> =>
    new RedisAdapter<TUser>(client)
}
