import { getAuthorizationServer, type DiscoveryCache } from './discovery'
import type { ResolvedBezzieConfig } from './index'

/**
 * CSP directive fragments the OAuth flow needs, keyed by directive name.
 * Origins only (no paths) — merge these into the app's own
 * Content-Security-Policy. Bezzie does not own the app's CSP: it has its own
 * `script-src`, `style-src`, `img-src`, nonces, and report endpoints, so this
 * returns fragments for the app to merge rather than a finished policy
 * string.
 */
export type CspContributions = Record<string, string[]>

/**
 * Returns the CSP directive fragments bezzie's OAuth flow needs, derived
 * from OIDC discovery. Reuses the existing {@link DiscoveryCache} — calling
 * this does not trigger an extra discovery round trip.
 *
 * - `form-action` — the load-bearing directive. Covers the
 *   `authorization_endpoint` origin (the redirect target of `/auth/login`)
 *   and the logout origin, `providerOverrides.logoutUrl` when set, otherwise
 *   `end_session_endpoint`. A strict `form-action 'self'` app-wide policy is
 *   a common hardening default and it breaks the login redirect without
 *   this.
 * - `connect-src` / `frame-src` — empty by default. In a correct BFF
 *   architecture, browser-side code never talks to the IdP directly (the
 *   token exchange happens server-side in the callback handler, which is
 *   not subject to the browser's CSP at all), and bezzie does not use
 *   silent-auth iframes. Returning origins here on the assumption a consumer
 *   might need them would make every consumer's CSP weaker than it needs to
 *   be for no reason.
 */
export async function cspContributions<TUser extends Record<string, unknown> = Record<string, unknown>>(
  config: ResolvedBezzieConfig<TUser>,
  cache: DiscoveryCache
): Promise<CspContributions> {
  const as = await getAuthorizationServer(config, cache)

  const formActionOrigins = new Set<string>()

  if (as.authorization_endpoint) {
    formActionOrigins.add(new URL(as.authorization_endpoint).origin)
  }

  if (config.providerOverrides?.logoutUrl) {
    formActionOrigins.add(new URL(config.providerOverrides.logoutUrl).origin)
  } else if (as.end_session_endpoint) {
    formActionOrigins.add(new URL(as.end_session_endpoint).origin)
  }

  return {
    'form-action': Array.from(formActionOrigins),
    'connect-src': [],
    'frame-src': [],
  }
}
