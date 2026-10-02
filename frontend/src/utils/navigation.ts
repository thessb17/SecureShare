/**
 * Safe internal navigation targets.
 *
 * React Router 6.30.6 (the latest 6.x) carries GHSA-wrjc-x8rr-h8h6: a
 * backslash in a `<Link to>` / `useNavigate()` target can be parsed as a
 * protocol-relative URL by some browsers and navigate off-site. The only
 * upstream fix is React Router 7, a breaking major we are not taking here.
 *
 * Instead every redirect target in this app is funnelled through
 * `safeInternalPath`, which accepts nothing but a single-slash-rooted local
 * path. That removes the open-redirect regardless of what the router does
 * with the string, and it is the correct hygiene for a login `?next=`-style
 * parameter anyway.
 */

/** Paths a redirect is allowed to land on when the target is untrusted. */
const FALLBACK = '/app'

export function safeInternalPath(candidate: unknown, fallback: string = FALLBACK): string {
  if (typeof candidate !== 'string' || candidate.length === 0) return fallback

  // Reject anything that is not a plain, rooted, local path.
  //   "//evil.com"      protocol-relative
  //   "/\evil.com"      backslash variant (GHSA-wrjc-x8rr-h8h6)
  //   "\\evil.com"      backslash variant
  //   "https://evil"    absolute URL
  //   "javascript:..."  scheme injection
  if (!candidate.startsWith('/')) return fallback
  if (candidate.startsWith('//')) return fallback
  if (candidate.includes('\\')) return fallback
  if (candidate.includes('://')) return fallback

  // Control characters can be used to smuggle the checks above past a parser.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(candidate)) return fallback

  // A decoded form must still be a local path (e.g. "/%2f%2fevil.com").
  try {
    const decoded = decodeURIComponent(candidate)
    if (decoded.startsWith('//') || decoded.includes('\\') || decoded.includes('://')) {
      return fallback
    }
  } catch {
    return fallback
  }

  return candidate
}
