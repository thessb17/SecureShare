/**
 * Open-redirect guard. Mitigates GHSA-wrjc-x8rr-h8h6 in react-router 6.30.6
 * (no patched 6.x exists; the upstream fix is the v7 major).
 */
import { describe, expect, it } from 'vitest'
import { safeInternalPath } from '../utils/navigation'

describe('safeInternalPath', () => {
  it('passes ordinary internal paths through unchanged', () => {
    for (const path of ['/app', '/app/files', '/app/files/abc-123', '/app/admin/users?page=2']) {
      expect(safeInternalPath(path)).toBe(path)
    }
  })

  it.each([
    ['protocol-relative', '//evil.example.com'],
    ['protocol-relative with path', '//evil.example.com/steal'],
    ['backslash variant', '/\\evil.example.com'],
    ['double backslash', '\\\\evil.example.com'],
    ['absolute http', 'http://evil.example.com'],
    ['absolute https', 'https://evil.example.com'],
    ['embedded scheme', '/redirect?to=https://evil.example.com'],
    ['javascript scheme', 'javascript:alert(1)'],
    ['data scheme', 'data:text/html,<script>alert(1)</script>'],
    ['relative escape', '../../evil'],
    ['bare host', 'evil.example.com'],
    ['encoded protocol-relative', '/%2f%2fevil.example.com'],
    ['tab smuggling', '/\u0009/evil.example.com'],
    ['newline smuggling', '/\n//evil.example.com'],
    ['null byte', '/app\u0000//evil.example.com'],
  ])('refuses %s and falls back to /app', (_label, hostile) => {
    expect(safeInternalPath(hostile)).toBe('/app')
  })

  it('falls back for empty and non-string input', () => {
    expect(safeInternalPath('')).toBe('/app')
    expect(safeInternalPath(undefined)).toBe('/app')
    expect(safeInternalPath(null)).toBe('/app')
    expect(safeInternalPath(42)).toBe('/app')
    expect(safeInternalPath({ toString: () => '//evil.com' })).toBe('/app')
  })

  it('honours an explicit fallback', () => {
    expect(safeInternalPath('//evil.example.com', '/login')).toBe('/login')
  })

  it('never returns a value that could leave the origin', () => {
    const candidates = [
      '//evil.com',
      '/\\evil.com',
      'https://evil.com',
      '/%2f%2fevil.com',
      '\\/evil.com',
    ]
    for (const candidate of candidates) {
      const result = safeInternalPath(candidate)
      const resolved = new URL(result, 'https://secureshare.local')
      expect(resolved.origin).toBe('https://secureshare.local')
    }
  })
})
