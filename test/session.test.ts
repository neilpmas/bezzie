import { describe, it, expect, vi } from 'vitest'
import { env } from 'cloudflare:test'
import { CloudflareKVAdapter, RedisAdapter, MemoryAdapter, Session, RedisClient } from '../src/session'

const mockSession: Session = {
  accessToken: 'access-token',
  refreshToken: 'refresh-token',
  expiresAt: Math.floor(Date.now() / 1000) + 3600,
  createdAt: Math.floor(Date.now() / 1000),
  user: {
    sub: 'user-sub',
    email: 'user@example.com',
  },
}

describe('CloudflareKVAdapter', () => {
  const adapter = new CloudflareKVAdapter(env.SESSION_KV)

  it('get returns null for missing key', async () => {
    const session = await adapter.get('non-existent')
    expect(session).toBeNull()
  })

  it('set writes the session and get returns it', async () => {
    const sessionId = 'kv-session-id'
    await adapter.set(sessionId, mockSession, 3600)
    const session = await adapter.get(sessionId)
    expect(session).toEqual(mockSession)
  })

  it('delete removes the session', async () => {
    const sessionId = 'kv-delete-session-id'
    await adapter.set(sessionId, mockSession, 3600)
    await adapter.delete(sessionId)
    expect(await adapter.get(sessionId)).toBeNull()
  })
})

describe('RedisAdapter', () => {
  const store = new Map<string, string>()
  const mockRedis: RedisClient = {
    get: vi.fn(async (key: string) => store.get(key) || null),
    set: vi.fn(async (key: string, value: string) => {
      store.set(key, value)
      return 'OK'
    }),
    del: vi.fn(async (key: string) => {
      store.delete(key)
      return 1
    }),
  }
  const adapter = new RedisAdapter(mockRedis)

  it('get returns null for missing key', async () => {
    const session = await adapter.get('non-existent')
    expect(session).toBeNull()
  })

  it('set writes the session and get returns it', async () => {
    const sessionId = 'redis-session-id'
    await adapter.set(sessionId, mockSession, 3600)
    const session = await adapter.get(sessionId)
    expect(session).toEqual(mockSession)
    expect(mockRedis.set).toHaveBeenCalledWith(sessionId, JSON.stringify(mockSession), { ex: 3600 })
  })

  it('delete removes the session', async () => {
    const sessionId = 'redis-delete-session-id'
    await adapter.set(sessionId, mockSession, 3600)
    await adapter.delete(sessionId)
    expect(await adapter.get(sessionId)).toBeNull()
    expect(mockRedis.del).toHaveBeenCalledWith(sessionId)
  })
})

describe('MemoryAdapter', () => {
  const adapter = new MemoryAdapter()

  it('get returns null for missing key', async () => {
    const session = await adapter.get('non-existent')
    expect(session).toBeNull()
  })

  it('set writes the session and get returns it', async () => {
    const sessionId = 'mem-session-id'
    await adapter.set(sessionId, mockSession, 3600)
    const session = await adapter.get(sessionId)
    expect(session).toEqual(mockSession)
  })

  it('delete removes the session', async () => {
    const sessionId = 'mem-delete-session-id'
    await adapter.set(sessionId, mockSession, 3600)
    await adapter.delete(sessionId)
    expect(await adapter.get(sessionId)).toBeNull()
  })

  it('handles TTL expiry', async () => {
    vi.useFakeTimers()
    const sessionId = 'ttl-session-id'
    await adapter.set(sessionId, mockSession, 10)

    // Still there
    expect(await adapter.get(sessionId)).toEqual(mockSession)

    // Advance time
    vi.advanceTimersByTime(11000)

    expect(await adapter.get(sessionId)).toBeNull()
    vi.useRealTimers()
  })
})
