import type { Context, MiddlewareHandler } from 'hono'
import type { SessionAdapter } from './adapters/types'

/**
 * Per-isolate, in-memory counters keyed by bucket. This is the fast, zero
 * storage cost first line of defense: a flood from one source mostly lands
 * on one isolate (Workers reuse an isolate across requests) and gets caught
 * here without ever reaching the adapter. It is best-effort only — per
 * isolate, lost on eviction — which is why the adapter-backed tier below
 * exists for cross-isolate consistency.
 */
const memoryCounters = new Map<string, { count: number; windowStart: number }>()

function windowStartFor(windowSeconds: number, now: number): number {
  const windowMs = windowSeconds * 1000
  return Math.floor(now / windowMs) * windowMs
}

function checkMemoryCounter(bucket: string, limit: number, windowSeconds: number): boolean {
  const now = Date.now()
  const windowStart = windowStartFor(windowSeconds, now)
  const entry = memoryCounters.get(bucket)

  if (!entry || entry.windowStart !== windowStart) {
    memoryCounters.set(bucket, { count: 1, windowStart })
    return true
  }

  entry.count += 1
  return entry.count <= limit
}

/**
 * Checks and (if still under the limit) increments the rate-limit counter
 * for `bucket`. Returns `true` if the caller should proceed, `false` if the
 * caller should reject the request.
 *
 * `bucket` must fully identify the caller's rate-limit policy, not just the
 * key being limited — it is used as-is for both the in-memory and
 * adapter-backed counters, so two callers sharing a bucket string share a
 * counter even if they were configured with different limits/windows. Both
 * call sites below (`createRateLimiter`, and the auth-route limiter in
 * `routes.ts`) fold `limit`/`windowSeconds` into the bucket for this reason.
 *
 * Always fails open: an error reading or writing the counter store is
 * logged and treated as allowed. An auth library that cannot authenticate
 * anyone during a storage incident is a worse outage than the flood this
 * exists to defend against.
 *
 * Two tiers, in order:
 * 1. The in-memory pre-filter above — checked first, costs nothing, and
 *    rejects outright once a single isolate has seen `limit` requests this
 *    window. Once a flood trips this, it never reaches the adapter.
 * 2. An adapter-backed counter (`ratelimit:<bucket>:<windowStart>`), for
 *    requests the in-memory tier would allow. This is a read on every such
 *    request but only ever a *write* while still under the limit — once the
 *    global count reaches `limit`, further requests are rejected on the
 *    read alone, so a sustained flood does not keep consuming write quota.
 *
 * Note this bounds *burst rate*, not a hard total: a determined, sustained
 * attacker can still accumulate significant adapter writes over a long
 * enough period at the configured rate. It turns "exhausted in seconds" into
 * "would take a sustained, easily-detectable effort" — it is not a
 * substitute for edge-level protection (e.g. Cloudflare's own Rate Limiting
 * rules), which bounds the same traffic without touching this adapter's
 * quota at all. See the README's Security section.
 */
export async function checkRateLimit(
  adapter: SessionAdapter,
  bucket: string,
  limit: number,
  windowSeconds: number
): Promise<boolean> {
  if (!checkMemoryCounter(bucket, limit, windowSeconds)) {
    return false
  }

  const windowStart = windowStartFor(windowSeconds, Date.now())
  const key = `ratelimit:${bucket}:${windowStart}`

  try {
    const stored = await adapter.get(key)
    const count = stored && stored._type === 'ratelimit' ? stored.count : 0

    if (count >= limit) {
      return false
    }

    // KV-backed adapters reject a TTL under 60s, and the window is the
    // natural expiry for this record either way.
    await adapter.set(key, { _type: 'ratelimit', count: count + 1, windowStart }, Math.max(windowSeconds, 60))
    return true
  } catch (err) {
    console.error(
      'Bezzie: rate limit counter store failed, failing open:',
      err instanceof Error ? err.message : String(err)
    )
    return true
  }
}

let warnedNoClientIp = false

function warnNoClientIp(): void {
  if (warnedNoClientIp) return
  warnedNoClientIp = true
  console.warn(
    'Bezzie: could not derive a client IP for rate limiting (no CF-Connecting-IP header, ' +
      'and trustProxyHeaders is not enabled) — limiting is skipped for these requests rather ' +
      'than grouping every client into one shared bucket. Enable `trustProxyHeaders` only if ' +
      'you trust your upstream proxy to set X-Real-IP/X-Forwarded-For and strip client-supplied ' +
      'values, since otherwise a client can set these themselves to defeat the limiter.'
  )
}

/**
 * Best-effort client IP. `CF-Connecting-IP` is always trusted — it is set by
 * the Cloudflare edge and cannot be forged by the client. `X-Real-IP` /
 * `X-Forwarded-For` are only consulted when `trustProxyHeaders` is `true`,
 * because outside of a trusted proxy that strips client-supplied values,
 * these are attacker-controlled: a client can set them to anything, which
 * would both defeat the limiter and mint unbounded buckets in
 * `memoryCounters` — write-amplifying the exact quota this exists to
 * protect. Returns `undefined` when no trustworthy IP can be derived; the
 * caller should skip limiting in that case rather than fall back to a
 * single shared bucket, which would rate-limit all such clients together.
 */
export function getClientIp(c: Context, trustProxyHeaders = false): string | undefined {
  const cfConnectingIp = c.req.header('cf-connecting-ip')
  if (cfConnectingIp) return cfConnectingIp

  if (trustProxyHeaders) {
    const forwardedFor = c.req.header('x-forwarded-for')?.split(',')[0]?.trim()
    if (forwardedFor) return forwardedFor

    const realIp = c.req.header('x-real-ip')
    if (realIp) return realIp
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
   * Whether to trust `X-Real-IP`/`X-Forwarded-For` for IP derivation when no
   * `keyFn` is given and no authenticated user is present. `CF-Connecting-IP`
   * is always trusted. Only enable this behind a proxy you control that
   * strips client-supplied values for these headers — see {@link getClientIp}.
   * @default false
   */
  trustProxyHeaders?: boolean
}

async function defaultKeyFn(c: Context, trustProxyHeaders: boolean): Promise<string | undefined> {
  const user = (c.var as { user?: { sub: string } }).user
  return user?.sub ?? getClientIp(c, trustProxyHeaders)
}

/**
 * Creates a reusable Hono rate-limiting middleware backed by the given
 * adapter, for a consuming app's own routes — not just bezzie's auth routes.
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
export function createRateLimiter(adapter: SessionAdapter, options: RateLimiterOptions): MiddlewareHandler {
  const { limit, windowSeconds, keyFn, trustProxyHeaders = false } = options
  const bucketPrefix = `app:${limit}:${windowSeconds}`
  return async (c, next) => {
    const key = keyFn ? await keyFn(c) : await defaultKeyFn(c, trustProxyHeaders)
    if (!key) {
      warnNoClientIp()
      return next()
    }
    const allowed = await checkRateLimit(adapter, `${bucketPrefix}:${key}`, limit, windowSeconds)
    if (!allowed) {
      c.header('Retry-After', String(windowSeconds))
      return c.text('Too many requests', 429)
    }
    return next()
  }
}
