export interface Session {
  accessToken: string
  refreshToken: string
  expiresAt: number // unix timestamp
  user: {
    sub: string
    email?: string
    [key: string]: unknown
  }
}

export * from './adapters'
