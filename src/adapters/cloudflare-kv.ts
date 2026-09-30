import { Session } from '../session'
import { PKCEState, RateLimitRecord, SessionAdapter, SessionAdapterFactory } from './types'
import { SessionStoreError } from '../errors'
import type { RateLimitStore } from '../ratelimit'

export class CloudflareKVAdapter<TUser extends object = Record<string, unknown>>
  implements SessionAdapter<TUser>
{
  constructor(private kv: KVNamespace) {}

  async get(sessionId: string): Promise<Session<TUser> | PKCEState | RateLimitRecord | null> {
    return await this.kv.get<Session<TUser> | PKCEState | RateLimitRecord>(sessionId, 'json')
  }

  async set(
    sessionId: string,
    session: Session<TUser> | PKCEState | RateLimitRecord,
    ttlSeconds: number
  ): Promise<void> {
    if (ttlSeconds < 60) {
      throw new SessionStoreError(
        'session_storage_failed',
        'Bezzie: KV TTL must be at least 60 seconds'
      )
    }
    await this.kv.put(sessionId, JSON.stringify(session), {
      expirationTtl: ttlSeconds,
    })
  }

  async delete(sessionId: string): Promise<void> {
    await this.kv.delete(sessionId)
  }
}

/**
 * Creates a Cloudflare KV session adapter factory.
 */
export function cloudflareKVAdapter(kv: KVNamespace): SessionAdapterFactory {
  return <TUser extends Record<string, unknown> = Record<string, unknown>>(): SessionAdapter<TUser> =>
    new CloudflareKVAdapter<TUser>(kv)
}

/**
 * The subset of Cloudflare's Workers Rate Limiting binding that bezzie uses.
 * Declared structurally so no Workers types are needed to compile against it.
 */
export interface CloudflareRateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>
}

/**
 * A {@link RateLimitStore} backed by a Cloudflare Workers Rate Limiting
 * binding — purpose-built for hot counters, unlike KV.
 *
 * The binding's limit and period (10 or 60 seconds) are fixed in wrangler
 * config (`ratelimits[].simple`), so the `limit`/`windowSeconds` bezzie is
 * configured with are ignored here: the binding's policy applies, in
 * addition to bezzie's in-memory pre-filter. Counting is per Cloudflare
 * location and eventually consistent by design — permissive, not an
 * accurate accounting system.
 *
 * Set bezzie's `rateLimit.windowSeconds` (and ideally `limit`) to match the
 * binding's `period`/`limit`: the pre-filter and the `Retry-After` header
 * use bezzie's values, so a mismatch makes them contradict the binding.
 *
 * @example
 * ```typescript
 * rateLimit: { store: cloudflareRateLimitStore(env.AUTH_RATE_LIMITER), limit: 10, windowSeconds: 60 }
 * ```
 */
export function cloudflareRateLimitStore(binding: CloudflareRateLimitBinding): RateLimitStore {
  return {
    async hit(bucket) {
      const { success } = await binding.limit({ key: bucket })
      return success
    },
  }
}
