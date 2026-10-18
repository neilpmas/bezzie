import { describe, it, expect } from 'vitest'
import { isSafeRelativePath } from '../src/redirect'

describe('isSafeRelativePath', () => {
  it.each([
    '/',
    '/dashboard',
    '/dashboard?tab=1&x=%2F%2Fevil.com#section',
    '/a/b/c.html',
    '/%2F/evil.com',
    '/.//evil.com',
  ])('accepts %j', (path) => {
    expect(isSafeRelativePath(path)).toBe(true)
  })

  it.each([
    ['empty string', ''],
    ['no leading slash', 'dashboard'],
    ['absolute https URL', 'https://evil.com'],
    ['scheme-less host', 'evil.com'],
    ['javascript: URL', 'javascript:alert(1)'],
    ['protocol-relative', '//evil.com'],
    ['backslash after slash', '/\\evil.com'],
    ['backslash later in path', '/ok\\evil.com'],
    ['slash backslash slash', '/\\/evil.com'],
    ['tab after slash', '/\t/evil.com'],
    ['newline after slash', '/\n/evil.com'],
    ['carriage return', '/\r/evil.com'],
    ['NUL', '/\u0000evil.com'],
    ['DEL', '/\u007fevil.com'],
    ['oversized', '/' + 'a'.repeat(2048)],
  ])('rejects %s', (_label, path) => {
    expect(isSafeRelativePath(path)).toBe(false)
  })

  it('rejects non-strings', () => {
    expect(isSafeRelativePath(undefined)).toBe(false)
    expect(isSafeRelativePath(null)).toBe(false)
    expect(isSafeRelativePath(42)).toBe(false)
  })
})
