import { describe, it, expect } from 'vitest'
import { env } from 'cloudflare:test'
import { SessionStore, Session } from '../src/session'

describe('SessionStore', () => {
  const store = new SessionStore(env.SESSION_KV)

  const mockSession: Session = {
    accessToken: 'access-token',
    refreshToken: 'refresh-token',
    expiresAt: Date.now() + 3600 * 1000,
    user: {
      sub: 'user-sub',
      email: 'user@example.com',
    },
  }

  it('get returns null for missing key', async () => {
    const session = await store.get('non-existent')
    expect(session).toBeNull()
  })

  it('set writes the session and get returns it', async () => {
    const sessionId = 'test-session-id'
    await store.set(sessionId, mockSession, 3600)

    const session = await store.get(sessionId)
    expect(session).toEqual(mockSession)
  })

  it('delete removes the session', async () => {
    const sessionId = 'delete-session-id'
    await store.set(sessionId, mockSession, 3600)

    // Verify it exists
    expect(await store.get(sessionId)).toEqual(mockSession)

    // Delete it
    await store.delete(sessionId)

    // Verify it's gone
    expect(await store.get(sessionId)).toBeNull()
  })
})
