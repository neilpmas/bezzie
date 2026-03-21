export interface Session {
  accessToken: string
  refreshToken: string
  expiresAt: number // unix timestamp
  user: {
    sub: string
    email?: string
    [key: string]: unknown
  }
}

export class SessionStore {
  constructor(private kv: KVNamespace) {}

  async get(sessionId: string): Promise<Session | null> {
    const session = await this.kv.get<Session>(sessionId, 'json')
    return session
  }

  async set(sessionId: string, session: Session, ttlSeconds: number): Promise<void> {
    await this.kv.put(sessionId, JSON.stringify(session), {
      expirationTtl: ttlSeconds,
    })
  }

  async delete(sessionId: string): Promise<void> {
    await this.kv.delete(sessionId)
  }
}
