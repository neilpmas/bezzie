import { describe, it, expect } from 'vitest'
import { createBezzie, MemoryAdapter, providers, type BezzieConfig } from '../src'

describe('createBezzie', () => {
  it('returns an object with routes and middleware', () => {
    const auth = createBezzie({
      issuer: 'https://test.auth0.com',
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
      issuer: 'https://test.auth0.com',
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
    const required = ['issuer', 'clientId', 'clientSecret', 'adapter', 'baseUrl']
    for (const key of required) {
      const config: Partial<BezzieConfig> = {
        issuer: 'https://test.auth0.com',
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        adapter: new MemoryAdapter(),
        baseUrl: 'https://app.test.com',
      }
      delete config[key as keyof BezzieConfig]
      expect(() => createBezzie(config as BezzieConfig)).toThrow(`Bezzie: missing required config: ${key}`)
    }
  })

  it('throws an error if issuer is not https', () => {
    const config = {
      issuer: 'http://test.auth0.com',
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      adapter: new MemoryAdapter(),
      baseUrl: 'https://app.test.com',
    }
    expect(() => createBezzie(config)).toThrow('Bezzie: issuer must start with https://')
  })

  it('throws an error if issuer is not a valid URL', () => {
    const config = {
      issuer: 'https://not a valid url',
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      adapter: new MemoryAdapter(),
      baseUrl: 'https://app.test.com',
    }
    expect(() => createBezzie(config)).toThrow('Bezzie: issuer must be a valid URL')
  })
})

describe('providers', () => {
  it('auth0 returns the correct config shape', () => {
    const config = providers.auth0('test.auth0.com')
    expect(config).toEqual({
      issuer: 'https://test.auth0.com',
      providerHints: {
        logoutUrl: 'https://test.auth0.com/v2/logout',
      },
    })
  })

  it('okta returns the correct config shape', () => {
    const config = providers.okta('test.okta.com')
    expect(config).toEqual({
      issuer: 'https://test.okta.com/oauth2/default',
    })
  })

  it('keycloak returns the correct config shape', () => {
    const config = providers.keycloak('https://keycloak.com', 'myrealm')
    expect(config).toEqual({
      issuer: 'https://keycloak.com/realms/myrealm',
    })
  })

  it('google returns the correct config shape', () => {
    const config = providers.google()
    expect(config).toEqual({
      issuer: 'https://accounts.google.com',
    })
  })
})
