import { Session } from '../session'
import { PKCEState, SessionAdapter } from './types'

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
