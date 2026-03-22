import { Hono } from 'hono'
import { authRoutes } from './routes'

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
  middleware: () => (c: unknown, next: () => Promise<void>) => Promise<void>
}

export function createBezzie(config: BezzieConfig): Bezzie {
  const router = authRoutes(config)

  return {
    routes: () => router,
    middleware: () => async (_c, next) => {
      await next()
    },
  }
}
