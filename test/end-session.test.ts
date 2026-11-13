import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'
import { createBezzie, MemoryAdapter, type BezzieConfig, type Session } from '../src'
import { adapterFactory } from './helpers'
import * as oauth from 'oauth4webapi'

vi.mock('oauth4webapi', async () => {
  const actual = await vi.importActual('oauth4webapi')
  return {
    ...actual,
    discoveryRequest: vi.fn(),
    processDiscoveryResponse: vi.fn(),
    revocationRequest: vi.fn(),
    processRevocationResponse: vi.fn(),
  }
})

const ISSUER = 'https://test.auth0.com'

function liveSession(): Session {
  return {
    _type: 'session',
    accessToken: 'at',
    refreshToken: 'rt',
    idToken: 'idt',
    expiresAt: Math.floor(Date.now() / 1000) + 3600,
    createdAt: Math.floor(Date.now() / 1000),
    user: { sub: 'u1' },
  } as Session
}

function setup(overrides: Partial<BezzieConfig> = {}, endSessionOptions?: { revoke?: boolean }) {
  const adapter = new MemoryAdapter()
  const auth = createBezzie({
    issuer: ISSUER,
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    adapter: adapterFactory(adapter),
    baseUrl: 'https://app.test.com',
    rateLimit: { enabled: false },
    ...overrides,
  })
  const app = new Hono()
  app.get('/api/me', auth.middleware(), (c) => c.json({ sub: c.var.user.sub }))
  // An account-deletion-style route: ends the session, then returns its own response.
  app.delete('/api/account', async (c) => {
    const ended = await auth.endSession(c, endSessionOptions)
    return c.json({ ended })
  })
  return { adapter, app }
}

describe('auth.endSession(c)', () => {
  beforeEach(() => {
    vi.mocked(oauth.discoveryRequest).mockReset().mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processDiscoveryResponse).mockReset().mockResolvedValue({
      issuer: ISSUER,
      revocation_endpoint: `${ISSUER}/oauth/revoke`,
    } as oauth.AuthorizationServer)
    vi.mocked(oauth.revocationRequest).mockReset().mockResolvedValue({} as unknown as Response)
    vi.mocked(oauth.processRevocationResponse).mockReset().mockResolvedValue(undefined)
  })

  it('deletes the session, clears the cookie, and leaves the route response intact', async () => {
    const { adapter, app } = setup()
    await adapter.set('session:s1', liveSession(), 3600)
    const cookie = { Cookie: '__Host-session=s1' }

    expect((await app.request('/api/me', { headers: cookie })).status).toBe(200)

    const res = await app.request('/api/account', { method: 'DELETE', headers: cookie })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ended: true })
    const setCookie = res.headers.get('Set-Cookie') ?? ''
    expect(setCookie).toMatch(/^__Host-session=;/)
    expect(setCookie).toMatch(/Secure/)
    expect(setCookie).toMatch(/Path=\//)
    expect(await adapter.get('session:s1')).toBeNull()

    // middleware() now treats the same cookie as signed out.
    expect((await app.request('/api/me', { headers: cookie })).status).toBe(401)
  })

  it('uses a custom cookieName and non-secure cookies', async () => {
    const { adapter, app } = setup({ cookieName: 'my-sess', secureCookies: false })
    await adapter.set('session:s2', liveSession(), 3600)
    const cookie = { Cookie: 'my-sess=s2' }

    const res = await app.request('/api/account', { method: 'DELETE', headers: cookie })
    expect(await res.json()).toEqual({ ended: true })
    const setCookie = res.headers.get('Set-Cookie') ?? ''
    expect(setCookie).toMatch(/^my-sess=;/)
    expect(setCookie).not.toMatch(/Secure/)
    expect(await adapter.get('session:s2')).toBeNull()
    expect((await app.request('/api/me', { headers: cookie })).status).toBe(401)
  })

  it('is a no-op that resolves false when there is no session', async () => {
    const { app } = setup()
    const res = await app.request('/api/account', { method: 'DELETE' })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ended: false })
    expect(oauth.revocationRequest).not.toHaveBeenCalled()
  })

  it('resolves false for a cookie whose session is already gone, and still clears the cookie', async () => {
    const { app } = setup()
    const res = await app.request('/api/account', { method: 'DELETE', headers: { Cookie: '__Host-session=gone' } })
    expect(await res.json()).toEqual({ ended: false })
    expect(res.headers.get('Set-Cookie')).toMatch(/^__Host-session=;/)
  })

  it('revokes the refresh token by default', async () => {
    const { adapter, app } = setup()
    await adapter.set('session:s3', liveSession(), 3600)
    await app.request('/api/account', { method: 'DELETE', headers: { Cookie: '__Host-session=s3' } })
    expect(oauth.revocationRequest).toHaveBeenCalledTimes(1)
    expect(vi.mocked(oauth.revocationRequest).mock.calls[0][3]).toBe('rt')
  })

  it('skips revocation with { revoke: false }', async () => {
    const { adapter, app } = setup({}, { revoke: false })
    await adapter.set('session:s4', liveSession(), 3600)
    const res = await app.request('/api/account', { method: 'DELETE', headers: { Cookie: '__Host-session=s4' } })
    expect(await res.json()).toEqual({ ended: true })
    expect(oauth.revocationRequest).not.toHaveBeenCalled()
  })

  it('still ends the session locally when discovery or revocation fails', async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const { adapter, app } = setup()
      await adapter.set('session:s5', liveSession(), 3600)
      vi.mocked(oauth.discoveryRequest).mockRejectedValue(new Error('network down'))
      const res = await app.request('/api/account', { method: 'DELETE', headers: { Cookie: '__Host-session=s5' } })
      expect(res.status).toBe(200)
      expect(await res.json()).toEqual({ ended: true })
      expect(await adapter.get('session:s5')).toBeNull()

      vi.mocked(oauth.discoveryRequest).mockResolvedValue({} as unknown as Response)
      vi.mocked(oauth.revocationRequest).mockRejectedValue(new Error('revoke down'))
      await adapter.set('session:s6', liveSession(), 3600)
      const res2 = await app.request('/api/account', { method: 'DELETE', headers: { Cookie: '__Host-session=s6' } })
      expect(await res2.json()).toEqual({ ended: true })
      expect(await adapter.get('session:s6')).toBeNull()
    } finally {
      errorSpy.mockRestore()
    }
  })

  it('calls onLogout, and routes an onLogout error to onError', async () => {
    const onLogout = vi.fn().mockRejectedValue(new Error('hook boom'))
    const onError = vi.fn()
    const { adapter, app } = setup({ onLogout, onError })
    await adapter.set('session:s7', liveSession(), 3600)
    const res = await app.request('/api/account', { method: 'DELETE', headers: { Cookie: '__Host-session=s7' } })
    expect(await res.json()).toEqual({ ended: true })
    expect(onLogout).toHaveBeenCalledWith(expect.objectContaining({ user: { sub: 'u1' }, sessionId: 's7' }))
    expect(onError).toHaveBeenCalledWith(expect.any(Error), expect.objectContaining({ hook: 'onLogout' }))
  })
})
