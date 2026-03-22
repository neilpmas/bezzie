import { describe, it, expect } from 'vitest'
import { createBezzie, MemoryAdapter } from '../src/index'

describe('createBezzie', () => {
  it('returns an object with routes and middleware', () => {
    const auth = createBezzie({
      domain: 'test.auth0.com',
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      audience: 'https://api.test.com',
      adapter: new MemoryAdapter(),
      baseUrl: 'https://app.test.com',
    })

    expect(typeof auth.routes).toBe('function')
    expect(typeof auth.middleware).toBe('function')
  })

  it('routes() returns a Hono instance', () => {
    const config = {
      domain: 'test.auth0.com',
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      audience: 'https://api.test.com',
      adapter: new MemoryAdapter(),
      baseUrl: 'https://app.test.com',
    }

    const auth = createBezzie(config)
    const router = auth.routes()
    expect(router).toBeDefined()
    expect(typeof router.fetch).toBe('function')
  })

  it('throws an error if a required config field is missing', () => {
    const required = ['domain', 'clientId', 'clientSecret', 'adapter', 'baseUrl']
    for (const key of required) {
      const config: any = {
        domain: 'test.auth0.com',
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        adapter: new MemoryAdapter(),
        baseUrl: 'https://app.test.com',
      }
      delete config[key]
      expect(() => createBezzie(config)).toThrow(`Bezzie: missing required config: ${key}`)
    }
  })
})
