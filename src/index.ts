import { Hono, type MiddlewareHandler } from 'hono'
import { authRoutes } from './routes'
import { middleware, type Variables } from './middleware'

export interface BezzieConfig {
  domain: string
  clientId: string
  clientSecret: string
  audience: string
  kv: KVNamespace
  baseUrl: string
}

export interface Bezzie {
  routes: () => Hono
  middleware: () => MiddlewareHandler<{ Variables: Variables }>
}

export function createBezzie(config: BezzieConfig): Bezzie {
  const router = authRoutes(config)

  return {
    routes: () => router,
    middleware: () => middleware(config),
  }
}
