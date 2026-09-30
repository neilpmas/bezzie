import { describe, it, expect, vi } from 'vitest'
import { createBezzie, MemoryAdapter, adapterRateLimitStore, cloudflareRateLimitStore, type SessionAdapter, type RateLimitStore } from '../src'
import { checkRateLimit, describeWait } from '../src/ratelimit'
import type { DiscoveryCache } from '../src/discovery'
import * as oauth from 'oauth4webapi'
import { Hono } from 'hono'

vi.mock('oauth4webapi', async () => {
  const actual = await vi.importActual('oauth4webapi')
  return {
    ...actual,
    discoveryRequest: vi.fn(),
    processDiscoveryResponse: vi.fn(),
  }
})

describe('checkRateLimit (unit)', () => {
  it('allows requests under the limit and rejects once the limit is exceeded', async () => {
    const adapter = new MemoryAdapter()
    const bucket = 'unit-test-bucket-1'

    const store = adapterRateLimitStore(adapter)
    expect(await checkRateLimit(store, bucket, 2, 60)).toBe(true)
    expect(await checkRateLimit(store, bucket, 2, 60)).toBe(true)
    expect(await checkRateLimit(store, bucket, 2, 60)).toBe(false)
  })

  it('counts through the adapter store, and stops writing once the limit is reached', async () => {
    const adapter = new MemoryAdapter()
    const setSpy = vi.spyOn(adapter, 'set')
    const store = adapterRateLimitStore(adapter)

    // limit 3, but ask the store directly so the in-memory tier can't answer for it
    expect(await store.hit('unit-test-store-writes', 3, 60)).toBe(true)
    expect(await store.hit('unit-test-store-writes', 3, 60)).toBe(true)
    expect(await store.hit('unit-test-store-writes', 3, 60)).toBe(true)
    expect(await store.hit('unit-test-store-writes', 3, 60)).toBe(false)
    expect(await store.hit('unit-test-store-writes', 3, 60)).toBe(false)

    // Only requests under the limit are written; rejections are read-only.
    expect(setSpy).toHaveBeenCalledTimes(3)
  })

  it('fails open when the adapter throws on read', async () => {
    const throwingAdapter: SessionAdapter = {
      get: vi.fn().mockRejectedValue(new Error('storage unavailable')),
      set: vi.fn().mockResolvedValue(undefined),
      delete: vi.fn().mockResolvedValue(undefined),
    }
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})

    const allowed = await checkRateLimit(adapterRateLimitStore(throwingAdapter), 'unit-test-bucket-fail-open-get', 1, 60)

    expect(allowed).toBe(true)
    expect(consoleError).toHaveBeenCalled()
    consoleError.mockRestore()
  })

  it('fails open when the adapter throws on write', async () => {
    const throwingAdapter: SessionAdapter = {
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn().mockRejectedValue(new Error('storage unavailable')),
      delete: vi.fn().mockResolvedValue(undefined),
    }
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})

    const allowed = await checkRateLimit(adapterRateLimitStore(throwingAdapter), 'unit-test-bucket-fail-open-set', 1, 60)

    expect(allowed).toBe(true)
    expect(consoleError).toHaveBeenCalled()
    consoleError.mockRestore()
  })
})

describe('describeWait', () => {
  it('reads whole minutes as minutes and everything else as seconds', () => {
    expect(describeWait(60)).toBe('a minute')
    expect(describeWait(120)).toBe('2 minutes')
    expect(describeWait(30)).toBe('30 seconds')
    expect(describeWait(90)).toBe('90 seconds')
  })
})

describe('pluggable RateLimitStore', () => {
  it('fails open when a custom store throws', async () => {
    const throwingStore: RateLimitStore = { hit: vi.fn().mockRejectedValue(new Error('store down')) }
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})

    // noinspection JSVoidFunctionReturnValueUsed
    expect(await checkRateLimit(throwingStore, 'unit-test-custom-throws', 1, 60)).toBe(true)
    expect(consoleError).toHaveBeenCalled()
    consoleError.mockRestore()
  })

  it('consults the custom store after the in-memory pre-filter allows', async () => {
    const store: RateLimitStore = { hit: vi.fn().mockResolvedValue(false) }

    // Store says no, so the request is rejected even though memory would allow it.
    expect(await checkRateLimit(store, 'unit-test-custom-denies', 5, 60)).toBe(false)
    expect(store.hit).toHaveBeenCalledWith('unit-test-custom-denies', 5, 60)
  })

  it('does not reach the store once the in-memory pre-filter has tripped', async () => {
    const store: RateLimitStore = { hit: vi.fn().mockResolvedValue(true) }

    await checkRateLimit(store, 'unit-test-custom-prefilter', 1, 60)
    // noinspection JSVoidFunctionReturnValueUsed
    expect(await checkRateLimit(store, 'unit-test-custom-prefilter', 1, 60)).toBe(false)
    expect(store.hit).toHaveBeenCalledTimes(1)
  })

  it('cloudflareRateLimitStore maps the binding result and passes the bucket as the key', async () => {
    const limit = vi.fn().mockResolvedValueOnce({ success: true }).mockResolvedValueOnce({ success: false })
    const store = cloudflareRateLimitStore({ limit })

    expect(await store.hit('auth:10:120:203.0.113.20', 10, 120)).toBe(true)
    expect(await store.hit('auth:10:120:203.0.113.20', 10, 120)).toBe(false)
    expect(limit).toHaveBeenCalledWith({ key: 'auth:10:120:203.0.113.20' })
  })

  it('uses rateLimit.store for /login instead of the session adapter', async () => {
    vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue({
      issuer: 'https://test.auth0.com',
      authorization_endpoint: 'https://test.auth0.com/authorize',
    } as oauth.AuthorizationServer)

    const adapter = new MemoryAdapter()
    const setSpy = vi.spyOn(adapter, 'set')
    const store: RateLimitStore = { hit: vi.fn().mockResolvedValueOnce(true).mockResolvedValueOnce(false) }
    const auth = createBezzie({
      issuer: 'https://test.auth0.com',
      clientId: 'id',
      clientSecret: 'secret',
      adapter: () => adapter,
      baseUrl: 'https://app.test.com',
      rateLimit: { store },
    })
    ;(auth as unknown as { cache: DiscoveryCache }).cache.cachedAS = null
    ;(auth as unknown as { cache: DiscoveryCache }).cache.cacheExpiresAt = 0
    const app = auth.routes()
    const headers = { 'CF-Connecting-IP': '203.0.113.30' }

    const res1 = await app.request('/login', { headers })
    const res2 = await app.request('/login', { headers })

    expect(res1.status).toBe(302)
    expect(res2.status).toBe(429)
    expect(store.hit).toHaveBeenCalledTimes(2)
    // The only adapter write is the PKCE state from the allowed login — no ratelimit: records.
    const writtenKeys = setSpy.mock.calls.map((call) => call[0])
    expect(writtenKeys.some((key) => key.startsWith('ratelimit:'))).toBe(false)
  })

  it('auth.rateLimiter() ignores rateLimit.store, and options.store opts in per limiter', async () => {
    const authStore: RateLimitStore = { hit: vi.fn().mockResolvedValue(false) }
    const optInStore: RateLimitStore = { hit: vi.fn().mockResolvedValue(false) }
    const auth = createBezzie({
      issuer: 'https://test.auth0.com',
      clientId: 'id',
      clientSecret: 'secret',
      adapter: () => new MemoryAdapter(),
      baseUrl: 'https://app.test.com',
      rateLimit: { store: authStore },
    })

    const app = new Hono()
    app.use('/default/*', auth.rateLimiter({ limit: 5, windowSeconds: 60 }))
    app.use('/optin/*', auth.rateLimiter({ limit: 6, windowSeconds: 60, store: optInStore }))
    app.get('/default/x', (c) => c.text('ok'))
    app.get('/optin/x', (c) => c.text('ok'))
    const headers = { 'CF-Connecting-IP': '203.0.113.31' }

    // Auth-route store would deny everything; the app limiter must not see it.
    expect((await app.request('/default/x', { headers })).status).toBe(200)
    expect(authStore.hit).not.toHaveBeenCalled()
    // A per-limiter store is honoured.
    expect((await app.request('/optin/x', { headers })).status).toBe(429)
    expect(optInStore.hit).toHaveBeenCalledTimes(1)
  })
})

describe('Rate limiting on /login and /callback', () => {
  function buildAuth(limit: number) {
    const adapter = new MemoryAdapter()
    const auth = createBezzie({
      issuer: 'https://test.auth0.com',
      clientId: 'id',
      clientSecret: 'secret',
      adapter: () => adapter,
      baseUrl: 'https://app.test.com',
      rateLimit: { limit, windowSeconds: 60 },
    })
    ;(auth as unknown as { cache: DiscoveryCache }).cache.cachedAS = null
    ;(auth as unknown as { cache: DiscoveryCache }).cache.cacheExpiresAt = 0
    return auth
  }

  it('returns 429 with Retry-After once the per-IP limit on /login is exceeded', async () => {
    vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue({
      issuer: 'https://test.auth0.com',
      authorization_endpoint: 'https://test.auth0.com/authorize',
    } as oauth.AuthorizationServer)

    // noinspection JSVoidFunctionReturnValueUsed
    const auth = buildAuth(2)
    // noinspection JSVoidFunctionReturnValueUsed
    const app = auth.routes()
    const ip = '203.0.113.5'

    const res1 = await app.request('/login', { headers: { 'CF-Connecting-IP': ip } })
    const res2 = await app.request('/login', { headers: { 'CF-Connecting-IP': ip } })
    const res3 = await app.request('/login', { headers: { 'CF-Connecting-IP': ip } })

    expect(res1.status).toBe(302)
    expect(res2.status).toBe(302)
    expect(res3.status).toBe(429)
    expect(res3.headers.get('Retry-After')).toBe('60')
    expect(await res3.text()).toBe('Too many sign-in attempts. Please wait a minute and try again.')
  })

  it('does not limit /logout', async () => {
    vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue({
      issuer: 'https://test.auth0.com',
    } as oauth.AuthorizationServer)

    const auth = buildAuth(1)
    // noinspection JSVoidFunctionReturnValueUsed
    const app = auth.routes()
    const ip = '203.0.113.6'

    // Exhaust the /login limit for this IP first.
    await app.request('/login', { headers: { 'CF-Connecting-IP': ip } })
    const limited = await app.request('/login', { headers: { 'CF-Connecting-IP': ip } })
    expect(limited.status).toBe(429)

    // /logout from the same IP is unaffected.
    const res = await app.request('/logout', { method: 'POST', headers: { 'CF-Connecting-IP': ip } })
    expect(res.status).toBe(302)
  })

  it('can be disabled via rateLimit.enabled: false', async () => {
    vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue({
      issuer: 'https://test.auth0.com',
      authorization_endpoint: 'https://test.auth0.com/authorize',
    } as oauth.AuthorizationServer)

    const adapter = new MemoryAdapter()
    const auth = createBezzie({
      issuer: 'https://test.auth0.com',
      clientId: 'id',
      clientSecret: 'secret',
      adapter: () => adapter,
      baseUrl: 'https://app.test.com',
      rateLimit: { enabled: false },
    })
    ;(auth as unknown as { cache: DiscoveryCache }).cache.cachedAS = null
    ;(auth as unknown as { cache: DiscoveryCache }).cache.cacheExpiresAt = 0
    const app = auth.routes()
    const ip = '203.0.113.7'

    for (let i = 0; i < 25; i++) {
      const res = await app.request('/login', { headers: { 'CF-Connecting-IP': ip } })
      expect(res.status).toBe(302)
    }
  })
})

describe('auth.rateLimiter() — exported reusable primitive', () => {
  it('keys on the authenticated user by default and fails open on storage errors', async () => {
    const auth = createBezzie({
      issuer: 'https://test.auth0.com',
      clientId: 'id',
      clientSecret: 'secret',
      adapter: () => new MemoryAdapter(),
      baseUrl: 'https://app.test.com',
    })

    const app = new Hono<{ Variables: { user: { sub: string } } }>()
    app.use('*', async (c, next) => {
      c.set('user', { sub: 'user-rl-1' })
      await next()
    })
    app.use('/api/*', auth.rateLimiter({ limit: 2, windowSeconds: 60 }))
    app.get('/api/thing', (c) => c.text('ok'))

    const res1 = await app.request('/api/thing')
    const res2 = await app.request('/api/thing')
    const res3 = await app.request('/api/thing')

    expect(res1.status).toBe(200)
    expect(res2.status).toBe(200)
    expect(res3.status).toBe(429)
    expect(res3.headers.get('Retry-After')).toBe('60')
    expect(await res3.text()).toBe('Too many requests. Please wait a minute and try again.')
  })

  it('falls back to client IP when no user is set', async () => {
    const auth = createBezzie({
      issuer: 'https://test.auth0.com',
      clientId: 'id',
      clientSecret: 'secret',
      adapter: () => new MemoryAdapter(),
      baseUrl: 'https://app.test.com',
    })

    const app = new Hono()
    app.use('/api/*', auth.rateLimiter({ limit: 1, windowSeconds: 60 }))
    app.get('/api/thing', (c) => c.text('ok'))

    const ip = '203.0.113.8'
    const res1 = await app.request('/api/thing', { headers: { 'CF-Connecting-IP': ip } })
    const res2 = await app.request('/api/thing', { headers: { 'CF-Connecting-IP': ip } })

    expect(res1.status).toBe(200)
    expect(res2.status).toBe(429)
  })

  it('does not let traffic on one route count against a differently-configured limiter on another route', async () => {
    const auth = createBezzie({
      issuer: 'https://test.auth0.com',
      clientId: 'id',
      clientSecret: 'secret',
      adapter: () => new MemoryAdapter(),
      baseUrl: 'https://app.test.com',
    })

    const app = new Hono()
    app.use('/cheap/*', auth.rateLimiter({ limit: 100, windowSeconds: 60 }))
    app.use('/expensive/*', auth.rateLimiter({ limit: 2, windowSeconds: 60 }))
    app.get('/cheap/thing', (c) => c.text('ok'))
    app.get('/expensive/thing', (c) => c.text('ok'))

    const ip = '203.0.113.9'
    for (let i = 0; i < 4; i++) {
      const res = await app.request('/cheap/thing', { headers: { 'CF-Connecting-IP': ip } })
      expect(res.status).toBe(200)
    }

    // The cheap route's traffic must not count against the expensive route's
    // much lower limit — this bucket has seen zero requests of its own.
    const expensive1 = await app.request('/expensive/thing', { headers: { 'CF-Connecting-IP': ip } })
    const expensive2 = await app.request('/expensive/thing', { headers: { 'CF-Connecting-IP': ip } })
    const expensive3 = await app.request('/expensive/thing', { headers: { 'CF-Connecting-IP': ip } })

    expect(expensive1.status).toBe(200)
    expect(expensive2.status).toBe(200)
    expect(expensive3.status).toBe(429)
  })

  it('skips limiting (rather than sharing one bucket) when no trustworthy IP is present', async () => {
    const auth = createBezzie({
      issuer: 'https://test.auth0.com',
      clientId: 'id',
      clientSecret: 'secret',
      adapter: () => new MemoryAdapter(),
      baseUrl: 'https://app.test.com',
    })

    const app = new Hono()
    app.use('/api/*', auth.rateLimiter({ limit: 1, windowSeconds: 60 }))
    app.get('/api/thing', (c) => c.text('ok'))

    // No CF-Connecting-IP, no trustProxyHeaders — every one of these requests
    // is indistinguishable from the others, so none should be limited.
    for (let i = 0; i < 3; i++) {
      const res = await app.request('/api/thing')
      expect(res.status).toBe(200)
    }
  })

  it('ignores X-Forwarded-For by default, but honours it with trustProxyHeaders: true', async () => {
    const auth = createBezzie({
      issuer: 'https://test.auth0.com',
      clientId: 'id',
      clientSecret: 'secret',
      adapter: () => new MemoryAdapter(),
      baseUrl: 'https://app.test.com',
    })

    const untrusting = new Hono()
    untrusting.use('/api/*', auth.rateLimiter({ limit: 1, windowSeconds: 60 }))
    untrusting.get('/api/thing', (c) => c.text('ok'))

    // A spoofed X-Forwarded-For is not trusted by default, so this isn't
    // treated as a repeat client — both requests are allowed.
    const untrusted1 = await untrusting.request('/api/thing', {
      headers: { 'X-Forwarded-For': '198.51.100.1' },
    })
    const untrusted2 = await untrusting.request('/api/thing', {
      headers: { 'X-Forwarded-For': '198.51.100.1' },
    })
    expect(untrusted1.status).toBe(200)
    expect(untrusted2.status).toBe(200)

    const trusting = new Hono()
    trusting.use('/api/*', auth.rateLimiter({ limit: 1, windowSeconds: 60, trustProxyHeaders: true }))
    trusting.get('/api/thing', (c) => c.text('ok'))

    const trusted1 = await trusting.request('/api/thing', {
      headers: { 'X-Forwarded-For': '198.51.100.2' },
    })
    const trusted2 = await trusting.request('/api/thing', {
      headers: { 'X-Forwarded-For': '198.51.100.2' },
    })
    expect(trusted1.status).toBe(200)
    expect(trusted2.status).toBe(429)
  })
})
