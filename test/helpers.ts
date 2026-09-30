import type { SessionAdapter, SessionAdapterFactory } from '../src'

/**
 * Wraps an existing adapter instance as a `SessionAdapterFactory`, so a test
 * can keep a handle on the same instance to read/write it directly.
 * `TUser` only exists at the type level, so the cast has no runtime effect.
 */
export function adapterFactory<T extends object>(adapter: SessionAdapter<T>): SessionAdapterFactory {
  return <TUser extends Record<string, unknown>>() => adapter as unknown as SessionAdapter<TUser>
}
