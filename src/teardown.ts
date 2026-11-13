import type { Context } from 'hono'
import { getCookie, deleteCookie } from 'hono/cookie'
import * as oauth from 'oauth4webapi'
import { getAuthorizationServer, type DiscoveryCache } from './discovery'
import type { Session } from './session'
import type { ResolvedBezzieConfig } from './index'

/**
 * The session cookie name, shared by the routes, the middleware and
 * `endSession()` so they can never disagree.
 */
export function sessionCookieName(config: Pick<ResolvedBezzieConfig, 'cookieName' | 'secureCookies'>): string {
  return config.cookieName ?? (config.secureCookies !== false ? '__Host-session' : 'session')
}

/**
 * What was in the session that `endLocalSession` just removed. All fields are
 * undefined when the request carried no session cookie or no live session.
 */
export interface EndedSession<TUser extends object> {
  sessionId?: string
  user?: Session<TUser>['user']
  idToken?: string
  refreshToken?: string
}

/**
 * Ends the request's session locally: deletes it from the adapter, runs
 * `onLogout` (errors routed to `onError`), and clears the session cookie.
 * Never talks to the IdP, so it cannot fail on a discovery outage.
 */
export async function endLocalSession<TUser extends object>(
  c: Context,
  config: ResolvedBezzieConfig<TUser>
): Promise<EndedSession<TUser>> {
  const ended: EndedSession<TUser> = {}
  const sessionId = getCookie(c, sessionCookieName(config))

  if (sessionId) {
    ended.sessionId = sessionId
    const session = await config.adapter.get(`session:${sessionId}`)
    if (session && session._type === 'session') {
      ended.user = session.user
      ended.idToken = session.idToken
      ended.refreshToken = session.refreshToken
    }
    await config.adapter.delete(`session:${sessionId}`)

    if (config.onLogout && ended.user) {
      try {
        await config.onLogout({ user: ended.user, sessionId, c })
      } catch (err) {
        const handler = config.onError ?? ((e: unknown) => console.error('Bezzie: onLogout hook threw:', e instanceof Error ? e.message : String(e)))
        handler(err, { hook: 'onLogout', c })
      }
    }
  }

  // Cleared even without a live session, so a stale cookie never lingers.
  deleteCookie(c, sessionCookieName(config), {
    path: '/',
    secure: config.secureCookies !== false,
    httpOnly: true,
    sameSite: 'Lax',
  })

  return ended
}

/**
 * S12: best-effort revoke of the refresh token at the IdP, so the tokens are
 * invalidated server-side, not just locally. Never throws.
 */
export async function revokeRefreshToken<TUser extends object>(
  config: ResolvedBezzieConfig<TUser>,
  as: oauth.AuthorizationServer,
  refreshToken: string | undefined
): Promise<void> {
  if (!refreshToken || !as.revocation_endpoint) {
    return
  }
  try {
    const client: oauth.Client = { client_id: config.clientId }
    const clientAuth = oauth.ClientSecretPost(config.clientSecret)
    const response = await oauth.revocationRequest(as, client, clientAuth, refreshToken, {
      signal: AbortSignal.timeout(5000),
    })
    await oauth.processRevocationResponse(response)
  } catch (err) {
    console.error('Bezzie: token revocation failed (session already ended locally):', err instanceof Error ? err.message : String(err))
  }
}

export interface EndSessionOptions {
  /**
   * Also revoke the refresh token at the IdP (best effort, as `/logout` does).
   * @default true
   */
  revoke?: boolean
}

/**
 * Implementation of `auth.endSession(c)`. Ends the session locally, then
 * best-effort revokes the refresh token. No redirect and never throws on IdP
 * trouble: the calling route carries on and returns its own response.
 * Resolves to true if there was a live session to end.
 */
export async function endSession<TUser extends object>(
  c: Context,
  config: ResolvedBezzieConfig<TUser>,
  cache: DiscoveryCache,
  options: EndSessionOptions = {}
): Promise<boolean> {
  const ended = await endLocalSession(c, config)

  if (options.revoke !== false && ended.refreshToken) {
    try {
      const as = await getAuthorizationServer(config, cache)
      await revokeRefreshToken(config, as, ended.refreshToken)
    } catch (err) {
      console.error('Bezzie: OIDC discovery failed in endSession (session ended locally, refresh token not revoked):', err instanceof Error ? err.message : String(err))
    }
  }

  return ended.user !== undefined
}
