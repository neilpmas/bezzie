export type BezzieErrorCode =
  | 'discovery_failed'
  | 'callback_invalid_state'
  | 'callback_provider_error'
  | 'token_exchange_failed'
  | 'refresh_failed'
  | 'refresh_token_revoked'
  | 'session_storage_failed'
  | 'session_not_found'
  | 'config_invalid'

export interface BezzieErrorOptions {
  cause?: unknown
  httpStatus?: number
  oauthError?: string
  oauthErrorDescription?: string
}

export class BezzieError extends Error {
  readonly code: BezzieErrorCode
  readonly httpStatus?: number
  readonly oauthError?: string
  readonly oauthErrorDescription?: string

  constructor(code: BezzieErrorCode, message: string, opts: BezzieErrorOptions = {}) {
    super(message, { cause: opts.cause })
    this.name = this.constructor.name
    this.code = code
    this.httpStatus = opts.httpStatus
    this.oauthError = opts.oauthError
    this.oauthErrorDescription = opts.oauthErrorDescription
    Object.setPrototypeOf(this, new.target.prototype)
  }
}

export class DiscoveryError extends BezzieError {
  constructor(message: string, opts?: BezzieErrorOptions) {
    super('discovery_failed', message, opts)
  }
}

export class CallbackError extends BezzieError {}
export class TokenExchangeError extends BezzieError {}
export class RefreshError extends BezzieError {}
export class SessionStoreError extends BezzieError {}
export class ConfigError extends BezzieError {}
