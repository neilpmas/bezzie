import { describe, it, expect, vi } from 'vitest'
import { Hono } from 'hono'
import { createBezzie, MemoryAdapter, memoryAdapter, type Variables } from '../src'
import { adapterFactory } from './helpers'
import * as oauth from 'oauth4webapi'

// Mock oauth4webapi
vi.mock('oauth4webapi', async () => {
  const actual = await vi.importActual('oauth4webapi')
  return {
    ...actual,
    discoveryRequest: vi.fn(),
    processDiscoveryResponse: vi.fn(),
    validateJwtAccessToken: vi.fn(),
  }
})

describe('Generics', () => {
  it('works with a custom user type', async () => {
    const issuer = 'https://test.auth0.com'
    // Default mock for discovery
    const mockAs = { issuer, jwks_uri: `${issuer}/jwks` }
    vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue(mockAs as oauth.AuthorizationServer)
    vi.mocked(oauth.validateJwtAccessToken).mockResolvedValue({} as oauth.JWTAccessTokenClaims)

    interface MyUser {
      role: 'admin' | 'user'
      preferred_username: string
    }

    const adapter = new MemoryAdapter<MyUser>()
    const config = {
      issuer: 'https://test.auth0.com',
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      adapter: adapterFactory(adapter),
      baseUrl: 'https://app.test.com',
    }

    const auth = createBezzie<MyUser>(config)
    const app = new Hono<{ Variables: Variables<MyUser> }>()

    app.use('/api/*', auth.middleware())
    app.get('/api/me', (c) => {
      const user = c.get('user')
      // These assertions verify the types at compile time (via tsc)
      // and at runtime (via vitest)
      const role: 'admin' | 'user' = user.role
      const username: string = user.preferred_username
      return c.json({ role, username })
    })

    const sessionId = 'test-session-id'
    const user: { sub: string; email?: string } & MyUser = { 
      sub: 'user-123', 
      email: 'user@example.com', 
      role: 'admin', 
      preferred_username: 'jdoe' 
    }
    
    await adapter.set(
      `session:${sessionId}`,
      {
        _type: 'session',
        accessToken: 'valid-token',
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        createdAt: Math.floor(Date.now() / 1000),
        user,
      },
      3600
    )

    const res = await app.request('/api/me', {
      headers: {
        Cookie: `__Host-session=${sessionId}`,
      },
    })

    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data).toEqual({ role: 'admin', username: 'jdoe' })
  })

  // Regression: TUser used to require an index signature, which rejected
  // `interface` user types. Enforced at compile time by `npm run typecheck:test`.
  it('accepts an interface user type with the built-in adapter factory', () => {
    interface AppUser {
      sub: string
      email?: string
      role: 'admin' | 'member'
    }

    const auth = createBezzie<AppUser>({
      issuer: 'https://test.auth0.com',
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      baseUrl: 'https://app.test.com',
      adapter: memoryAdapter(),
      mapClaims: (claims) => claims as AppUser,
      onLogin: ({ user }) => {
        const role: 'admin' | 'member' = user.role
        void role
      },
    })

    const app = new Hono<{ Variables: Variables<AppUser> }>()
    app.use('/api/*', auth.middleware())
    app.get('/api/role', (c) => c.json({ role: c.var.user.role }))

    expect(app).toBeDefined()
  })
})
