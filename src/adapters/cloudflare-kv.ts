import { Session } from '../session'
import { PKCEState, SessionAdapter, SessionAdapterFactory } from './types'
import { SessionStoreError } from '../errors'

export class CloudflareKVAdapter<TUser extends Record<string, unknown> = Record<string, unknown>>
  implements SessionAdapter<TUser>
{
  constructor(private kv: KVNamespace) {}

  async get(sessionId: string): Promise<Session<TUser> | PKCEState | null> {
    return await this.kv.get<Session<TUser> | PKCEState>(sessionId, 'json')
  }

  async set(
    sessionId: string,
    session: Session<TUser> | PKCEState,
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
