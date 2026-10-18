const MAX_RETURN_TO_LENGTH = 2048

// Browsers follow the WHATWG URL parser, which treats `\` as `/` and strips
// tab/CR/LF anywhere in a URL, so `/\evil.com` and `/<TAB>/evil.com` both
// resolve to `//evil.com` even though they pass a naive "starts with / but not
// //" check. Reject backslashes and all C0/DEL control characters outright.
function hasUnsafeChars(path: string): boolean {
  for (let i = 0; i < path.length; i++) {
    const code = path.charCodeAt(i)
    if (code === 0x5c || code <= 0x1f || code === 0x7f) return true
  }
  return false
}

/**
 * Whether `path` is safe to use as a post-login redirect target: a
 * same-origin, path-absolute reference and nothing a browser could reinterpret
 * as a different host.
 */
export function isSafeRelativePath(path: unknown): path is string {
  if (typeof path !== 'string' || path.length === 0 || path.length > MAX_RETURN_TO_LENGTH) {
    return false
  }
  if (!path.startsWith('/') || path.startsWith('//') || hasUnsafeChars(path)) {
    return false
  }
  // Defence in depth: resolve against a placeholder origin the way a browser
  // would and make sure it stays there.
  const base = 'https://bezzie.invalid'
  try {
    return new URL(path, base).origin === base
  } catch {
    return false
  }
}
