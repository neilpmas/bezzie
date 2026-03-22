import { describe, it, expect } from 'vitest'
import { createBezzie } from '../src/index'

describe('createBezzie', () => {
  it('returns an object with routes and middleware', () => {
    const auth = createBezzie({
      domain: 'test.auth0.com',
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      audience: 'https://api.test.com',
      kv: {} as KVNamespace,
      baseUrl: 'https://app.test.com',
    })

    expect(typeof auth.routes).toBe('function')
    expect(typeof auth.middleware).toBe('function')
  })

  it('routes() returns a Hono instance', () => {
    const auth = createBezzie({
      domain: 'test.auth0.com',
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      audience: 'https://api.test.com',
      kv: {} as KVNamespace,
      baseUrl: 'https://app.test.com',
    })

    const router = auth.routes()
    expect(router).toBeDefined()
    expect(typeof router.fetch).toBe('function')
  })
})
