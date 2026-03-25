import { Hono } from 'hono'
import { createBezzie, providers, cloudflareKV, type Variables } from '../../src'

/**
 * Environment bindings for the Worker
 */
type Bindings = {
  AUTH0_CLIENT_SECRET: string
  SESSION_KV: KVNamespace
}

/**
 * A complete minimal Workers app demonstrating Bezzie usage.
 */
export default {
  async fetch(request: Request, env: Bindings, ctx: ExecutionContext) {
    const baseUrl = new URL(request.url).origin

    // 1. createBezzie config with Auth0
    const auth = createBezzie({
      ...providers.auth0('your-tenant.auth0.com'),
      clientId: 'your-client-id',
      clientSecret: env.AUTH0_CLIENT_SECRET,
      audience: 'https://api.yourproject.com',
      adapter: cloudflareKV(env.SESSION_KV),
      baseUrl: baseUrl,
    })

    const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

    // 2. Mount auth routes
    // Provides: /auth/login, /auth/callback, /auth/logout
    app.route('/auth', auth.routes())

    // 3. A protected route that reads user info from c.var.user
    app.get('/api/me', auth.middleware(), (c) => {
      const user = c.var.user
      return c.json({ user })
    })

    // 4. A protected route that forwards to an upstream with Authorization header
    app.all('/api/proxy/*', auth.middleware(), async (c) => {
      const url = new URL(c.req.url)
      // Forward to your backend service (e.g., Spring Boot, Node.js)
      const target = `https://api.upstream.com${url.pathname.replace('/api/proxy', '')}${url.search}`
      
      const accessToken = c.var.accessToken

      return fetch(target, {
        method: c.req.method,
        headers: {
          ...c.req.header(),
          'Authorization': `Bearer ${accessToken}`
        },
        body: c.req.raw.body
      })
    })

    return app.fetch(request, env, ctx)
  }
}
