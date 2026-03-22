import { Hono, type MiddlewareHandler } from 'hono'
import { authRoutes } from './routes'
import { middleware, type Variables } from './middleware'

import { CloudflareKVAdapter, type SessionAdapter } from './session'

export interface BezzieConfig {
  domain: string
  clientId: string
  clientSecret: string
  audience?: string
  adapter: SessionAdapter
  baseUrl: string
}

function cloudflareKV(kv: KVNamespace): SessionAdapter {
  return new CloudflareKVAdapter(kv)
}

export interface Bezzie {
  routes: () => Hono
  middleware: () => MiddlewareHandler<{ Variables: Variables }>
}

function createBezzie(config: BezzieConfig): Bezzie {
  const required = ['domain', 'clientId', 'clientSecret', 'adapter', 'baseUrl']
  for (const key of required) {
    if (!config[key as keyof BezzieConfig]) {
      throw new Error(`Bezzie: missing required config: ${key}`)
    }
  }

  const router = authRoutes(config)

  return {
    routes: () => router,
    middleware: () => middleware(config),
  }
}

export { createBezzie, cloudflareKV }
export type { BezzieConfig }
export type { SessionAdapter, PKCEState, Session } from './session'
export { CloudflareKVAdapter, RedisAdapter, MemoryAdapter } from './session'
