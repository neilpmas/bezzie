import { Hono, type MiddlewareHandler } from 'hono'
import { authRoutes } from './routes'
import { middleware, type Variables } from './middleware'

import { CloudflareKVAdapter, type SessionAdapter } from './session'

export interface BezzieConfig {
  issuer: string
  clientId: string
  clientSecret: string
  audience?: string
  adapter: SessionAdapter
  baseUrl: string
  providerHints?: {
    logoutUrl?: string
    tokenEndpoint?: string
  }
}

export const providers = {
  auth0: (domain: string) => ({
    issuer: `https://${domain}`,
    providerHints: {
      logoutUrl: `https://${domain}/v2/logout`,
    },
  }),
  okta: (domain: string) => ({
    issuer: `https://${domain}/oauth2/default`,
  }),
  keycloak: (baseUrl: string, realm: string) => ({
    issuer: `${baseUrl}/realms/${realm}`,
  }),
  google: () => ({
    issuer: 'https://accounts.google.com',
  }),
}

function cloudflareKV(kv: KVNamespace): SessionAdapter {
  return new CloudflareKVAdapter(kv)
}

export interface Bezzie {
  routes: () => Hono
  middleware: () => MiddlewareHandler<{ Variables: Variables }>
}

function createBezzie(config: BezzieConfig): Bezzie {
  const required = ['issuer', 'clientId', 'clientSecret', 'adapter', 'baseUrl']
  for (const key of required) {
    if (!config[key as keyof BezzieConfig]) {
      throw new Error(`Bezzie: missing required config: ${key}`)
    }
  }

  if (!config.issuer.startsWith('https://')) {
    throw new Error('Bezzie: issuer must start with https://')
  }

  try {
    new URL(config.issuer)
  } catch (e) {
    throw new Error('Bezzie: issuer must be a valid URL')
  }

  const router = authRoutes(config)

  return {
    routes: () => router,
    middleware: () => middleware(config),
  }
}

export { createBezzie, cloudflareKV }
export type { SessionAdapter, PKCEState, Session } from './session'
export { CloudflareKVAdapter, RedisAdapter, MemoryAdapter } from './session'
