import { Hono } from 'hono'

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

export function createBezzie(_config: BezzieConfig): Bezzie {
  const router = new Hono()

  return {
    routes: () => router,
    middleware: () => async (_c, next) => {
      await next()
    },
  }
}
