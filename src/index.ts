import { Hono } from 'hono'

export interface PortcullisConfig {
  domain: string
  clientId: string
  clientSecret: string
  audience: string
  kv: KVNamespace
  baseUrl: string
}

export interface Portcullis {
  routes: () => Hono
  middleware: () => (c: unknown, next: () => Promise<void>) => Promise<void>
}

export function createPortcullis(_config: PortcullisConfig): Portcullis {
  const router = new Hono()

  return {
    routes: () => router,
    middleware: () => async (_c, next) => {
      await next()
    },
  }
}
