import type { Context, MiddlewareHandler } from 'hono'
import type { SessionAdapter } from './adapters'

/**
 * Per-isolate, in-memory counters keyed by bucket. This is the fast, zero
 * storage cost first line of defense: a flood from one source mostly lands
 * on one isolate (Workers reuse an isolate across requests) and gets caught
 * here without ever reaching the adapter. It is best-effort only — per
 * isolate, lost on eviction — which is why the adapter-backed tier below
 * exists for cross-isolate consistency.
 */
const memoryCounters = new Map<string, { count: number; windowStart: number; windowEnd: number }>()

/**
 * Upper bound on live buckets held in memory. Keys are derived from client
 * IPs, so without a cap a long-lived process (Node, Bun, Deno — or a Workers
 * isolate that stays warm) would grow this map by one entry per distinct
 * client forever. At the cap, expired buckets are swept first, then the
 * oldest are evicted — which at worst forgets an in-flight count, leaving the
 * store-backed tier to enforce the limit.
 */
export const MAX_MEMORY_COUNTERS = 10_000
const SWEEP_INTERVAL_MS = 1000
let lastSweep = 0

/** Number of buckets currently held by the in-memory tier. For tests. */
export function memoryCounterCount(): number {
  return memoryCounters.size
}

function makeRoomForCounter(now: number): void {
  if (memoryCounters.size < MAX_MEMORY_COUNTERS) return
  if (now - lastSweep >= SWEEP_INTERVAL_MS) {
    lastSweep = now
    for (const [key, entry] of memoryCounters) {
      if (entry.windowEnd <= now) memoryCounters.delete(key)
    }
  }
  while (memoryCounters.size >= MAX_MEMORY_COUNTERS) {
    const oldest = memoryCounters.keys().next()
    if (oldest.done) break
    memoryCounters.delete(oldest.value)
  }
}

function windowStartFor(windowSeconds: number, now: number): number {
  const windowMs = windowSeconds * 1000
  return Math.floor(now / windowMs) * windowMs
}

function checkMemoryCounter(bucket: string, limit: number, windowSeconds: number): boolean {
  const now = Date.now()
  const windowStart = windowStartFor(windowSeconds, now)
  const entry = memoryCounters.get(bucket)

  if (!entry || entry.windowStart !== windowStart) {
    if (!entry) makeRoomForCounter(now)
    memoryCounters.set(bucket, { count: 1, windowStart, windowEnd: windowStart + windowSeconds * 1000 })
    return true
  }

  entry.count += 1
  return entry.count <= limit
}

/**
 * Backing store for the cross-isolate tier of rate limiting.
 *
 * `hit` counts one request against `bucket` and resolves `true` if the
 * caller should proceed, `false` if it should be rejected. It may throw —
 * {@link checkRateLimit} treats any error as "allow" (fail open).
 *
 * `limit` and `windowSeconds` are the caller's configured policy. Stores
 * backed by a platform primitive with a fixed policy (such as Cloudflare's
 * Rate Limiting binding, whose limit and period live in wrangler config) may
 * ignore them; in that case the store's own policy applies in addition to
 * bezzie's in-memory pre-filter.
 */
export interface RateLimitStore {
  hit(bucket: string, limit: number, windowSeconds: number): Promise<boolean>
}

/**
 * The default store: counters kept in the same {@link SessionAdapter} used
 * for sessions and PKCE state (`ratelimit:<bucket>:<windowStart>`, TTL equal
 * to the window). A read on every request, but only a *write* while still
 * under the limit — once the global count reaches `limit`, further requests
 * are rejected on the read alone, so a sustained flood does not keep
 * consuming write quota.
 *
 * Portable, but a weak fit for hot counters on eventually consistent stores
 * like Cloudflare KV (reads are edge-cached, and a flood targets one hot
 * key). Prefer a purpose-built store (e.g. `cloudflareRateLimitStore`) where
 * one is available.
 */
export function adapterRateLimitStore<TUser extends object = Record<string, unknown>>(adapter: SessionAdapter<TUser>): RateLimitStore {
  return {
    async hit(bucket, limit, windowSeconds) {
      const windowStart = windowStartFor(windowSeconds, Date.now())
      const key = `ratelimit:${bucket}:${windowStart}`

      const stored = await adapter.get(key)
      const count = stored && stored._type === 'ratelimit' ? stored.count : 0

      if (count >= limit) {
        return false
      }

      // KV-backed adapters reject a TTL under 60s, and the window is the
      // natural expiry for this record either way.
      await adapter.set(key, { _type: 'ratelimit', count: count + 1, windowStart }, Math.max(windowSeconds, 60))
      return true
    },
  }
}

/**
 * Checks and (if still under the limit) increments the rate-limit counter
 * for `bucket`. Returns `true` if the caller should proceed, `false` if the
 * caller should reject the request.
 *
 * `bucket` must fully identify the caller's rate-limit policy, not just the
 * key being limited — it is used as-is for both the in-memory and
 * store-backed counters, so two callers sharing a bucket string share a
 * counter even if they were configured with different limits/windows. Both
 * call sites (`createRateLimiter`, and the auth-route limiter in
 * `routes.ts`) fold `limit`/`windowSeconds` into the bucket for this reason.
 *
 * Always fails open: an error from the store is logged and treated as
 * allowed. An auth library that cannot authenticate anyone during a storage
 * incident is a worse outage than the flood this exists to defend against.
 *
 * Two tiers, in order:
 * 1. The in-memory pre-filter above — checked first, costs nothing, and
 *    rejects outright once a single isolate has seen `limit` requests this
 *    window. Once a flood trips this, it never reaches the store.
 * 2. The {@link RateLimitStore}, for requests the in-memory tier would
 *    allow, giving cross-isolate consistency.
 *
 * Note this bounds *burst rate*, not a hard total: a determined, sustained
 * attacker can still accumulate significant store writes over a long enough
 * period at the configured rate. It is not a substitute for edge-level
 * protection (e.g. Cloudflare's own Rate Limiting rules). See the README's
 * Security section.
 */
export async function checkRateLimit(
  store: RateLimitStore,
  bucket: string,
  limit: number,
  windowSeconds: number
): Promise<boolean> {
  if (!checkMemoryCounter(bucket, limit, windowSeconds)) {
    return false
  }

  try {
    return await store.hit(bucket, limit, windowSeconds)
  } catch (err) {
    console.error(
      'Bezzie: rate limit counter store failed, failing open:',
      err instanceof Error ? err.message : String(err)
    )
    return true
  }
}

/**
 * Human-readable wait for the 429 body, consistent with the `Retry-After`
 * header: whole minutes read as "a minute" / "2 minutes", anything else in
 * seconds.
 */
export function describeWait(windowSeconds: number): string {
  if (windowSeconds >= 60 && windowSeconds % 60 === 0) {
    const minutes = windowSeconds / 60
    return minutes === 1 ? 'a minute' : `${minutes} minutes`
  }
  return `${windowSeconds} seconds`
}

let warnedNoClientIp = false

export function warnNoClientIp(): void {
  if (warnedNoClientIp) return
  warnedNoClientIp = true
  console.warn(
    'Bezzie: could not derive a trustworthy client IP for rate limiting — limiting is skipped for these ' +
      'requests rather than grouping every client into one shared bucket. CF-Connecting-IP is only ' +
      'trusted when running on Cloudflare Workers; elsewhere, and for X-Real-IP/X-Forwarded-For, enable ' +
      '`trustProxyHeaders` — but only if you trust your upstream proxy to set these headers and strip ' +
      'client-supplied values, since otherwise a client can set them itself to defeat the limiter.'
  )
}

function runningOnCloudflareWorkers(): boolean {
  const nav = (globalThis as { navigator?: { userAgent?: string } }).navigator
  return nav?.userAgent === 'Cloudflare-Workers'
}

/**
 * Collapses an address into the key its rate-limit bucket should use. IPv4 is
 * used as-is. IPv6 is reduced to its /64 prefix: a single subscriber or VPS is
 * normally handed a whole /64 (2^64 addresses), so keying on the full address
 * would let one host rotate through fresh buckets and never be limited.
 * IPv4-mapped IPv6 (`::ffff:1.2.3.4`) is treated as the IPv4 address.
 */
export function normalizeIp(raw: string): string {
  let ip = raw.trim().toLowerCase()
  if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1)
  const zone = ip.indexOf('%')
  if (zone !== -1) ip = ip.slice(0, zone)

  if (!ip.includes(':')) return ip

  const mapped = ip.match(/^(?:(?:0{1,4}:){5}|::)ffff:(\d{1,3}(?:\.\d{1,3}){3})$/)
  if (mapped) return mapped[1]

  // Expand `::` so the first four groups (the /64) can be read positionally.
  const halves = ip.split('::')
  if (halves.length > 2) return ip
  const head = halves[0] ? halves[0].split(':') : []
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const missing = 8 - head.length - tail.length
  if ((halves.length === 1 && head.length !== 8) || (halves.length === 2 && missing < 1)) return ip
  const groups = halves.length === 1 ? head : [...head, ...new Array<string>(missing).fill('0'), ...tail]
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return ip
  return `${groups.slice(0, 4).map((g) => g.padStart(4, '0')).join(':')}::/64`
}

/**
 * Best-effort client IP. `CF-Connecting-IP` is set by the Cloudflare edge and
 * cannot be forged by the client — but only when the request actually came
 * through it. It is therefore trusted when running on Cloudflare Workers
 * (where the platform guarantees that) or when `trustProxyHeaders` is on;
 * on Node/Bun/Deno a client can send the header itself. `X-Real-IP` /
 * `X-Forwarded-For` are only consulted when `trustProxyHeaders` is `true`,
 * because outside of a trusted proxy that strips client-supplied values,
 * these are attacker-controlled: a client can set them to anything, which
 * would both defeat the limiter and mint unbounded buckets in
 * `memoryCounters` — write-amplifying the exact quota this exists to
 * protect. Returns `undefined` when no trustworthy IP can be derived; the
 * caller should skip limiting in that case rather than fall back to a
 * single shared bucket, which would rate-limit all such clients together.
 * IPv6 addresses are returned as their /64 prefix (see {@link normalizeIp}).
 */
export function getClientIp(c: Context, trustProxyHeaders = false): string | undefined {
  if (trustProxyHeaders || runningOnCloudflareWorkers()) {
    const cfConnectingIp = c.req.header('cf-connecting-ip')
    if (cfConnectingIp) return normalizeIp(cfConnectingIp)
  }

  if (trustProxyHeaders) {
    const forwardedFor = c.req.header('x-forwarded-for')?.split(',')[0]?.trim()
    if (forwardedFor) return normalizeIp(forwardedFor)

    const realIp = c.req.header('x-real-ip')
    if (realIp) return normalizeIp(realIp)
  }

  return undefined
}

export interface RateLimiterOptions {
  /**
   * Max requests per window per key.
   */
  limit: number
  /**
   * Window size in seconds. Must be >= 60 to stay compatible with the
   * minimum TTL enforced by KV-backed adapters.
   */
  windowSeconds: number
  /**
   * Derives the bucket key for a request. Defaults to the authenticated
   * user's `sub` (set by bezzie's own middleware on `c.var.user`), falling
   * back to the client IP for unauthenticated requests. Return `undefined`
   * to skip limiting for a request (e.g. no identity and no trustworthy IP).
   *
   * Identity-keyed limiting is materially stronger than IP-only: IP breaks
   * down behind NAT/CGNAT, where one address can front a whole office or a
   * mobile carrier's subscriber pool.
   */
  keyFn?: (c: Context) => string | undefined | Promise<string | undefined>
  /**
   * Whether to trust `CF-Connecting-IP`/`X-Real-IP`/`X-Forwarded-For` for IP
   * derivation when no `keyFn` is given and no authenticated user is present.
   * `CF-Connecting-IP` is always trusted on Cloudflare Workers, but only
   * with this on elsewhere. Only enable this behind a proxy you control that
   * strips client-supplied values for these headers — see {@link getClientIp}.
   * @default false
   */
  trustProxyHeaders?: boolean
  /**
   * Backing store for this limiter's cross-isolate counters. Defaults to
   * counting through the session adapter; it does NOT inherit
   * `rateLimit.store` (which is for bezzie's own auth routes), because a
   * fixed-policy store such as a Cloudflare Rate Limiting binding would
   * silently override the `limit`/`windowSeconds` given here. See
   * {@link RateLimitStore}.
   */
  store?: RateLimitStore
}

async function defaultKeyFn(c: Context, trustProxyHeaders: boolean): Promise<string | undefined> {
  const user = (c.var as { user?: { sub: string } }).user
  return user?.sub ?? getClientIp(c, trustProxyHeaders)
}

/**
 * Creates a reusable Hono rate-limiting middleware backed by `defaultStore`
 * (overridable per limiter via `options.store`), for a consuming app's own routes — not just bezzie's auth routes.
 * Bezzie is the only component that already has identity resolved by the
 * time app routes run, so this can key on the authenticated user rather than
 * making every app re-derive that itself. Fails open on any storage error
 * (see {@link checkRateLimit}), and skips limiting (rather than lumping
 * everyone into one bucket) when no key can be derived.
 *
 * Each middleware instance gets its own namespace in the bucket, folding in
 * `limit`/`windowSeconds` — mounting two `rateLimiter()` instances with
 * different policies on different routes must not let one's traffic count
 * against the other's counter.
 */
export function createRateLimiter(defaultStore: RateLimitStore, options: RateLimiterOptions): MiddlewareHandler {
  const { limit, windowSeconds, keyFn, trustProxyHeaders = false, store = defaultStore } = options
  const bucketPrefix = `app:${limit}:${windowSeconds}`
  return async (c, next) => {
    const key = keyFn ? await keyFn(c) : await defaultKeyFn(c, trustProxyHeaders)
    if (!key) {
      warnNoClientIp()
      return next()
    }
    const allowed = await checkRateLimit(store, `${bucketPrefix}:${key}`, limit, windowSeconds)
    if (!allowed) {
      c.header('Retry-After', String(windowSeconds))
      return c.text(`Too many requests. Please wait ${describeWait(windowSeconds)} and try again.`, 429)
    }
    return next()
  }
}
