import crypto from 'crypto'

// Stable canonical JSON (recursively key-sorted) so signatures are reproducible
// across engines. Shared by builder and verifier.
export function canonicalJson(obj: unknown): string {
  if (Array.isArray(obj)) {
    return '[' + obj.map(v => canonicalJson(v)).join(',') + ']'
  }
  if (obj !== null && typeof obj === 'object') {
    const sorted = Object.keys(obj as Record<string, unknown>).sort()
    return '{' + sorted.map(k =>
      JSON.stringify(k) + ':' + canonicalJson((obj as Record<string, unknown>)[k])
    ).join(',') + '}'
  }
  return JSON.stringify(obj)
}

export function sha256(data: string): string {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex')
}

// Merkle-style hash over an ordered list of contents. Deterministic and
// order-sensitive (chunk order is part of provenance).
export function hashContents(contents: string[]): string {
  return sha256(contents.map(c => sha256(c)).join('|'))
}

export interface SigningKey {
  keyId:  string
  secret: string
}

export function signManifest(manifestHash: string, key: SigningKey): string {
  return crypto.createHmac('sha256', key.secret).update(manifestHash, 'utf8').digest('hex')
}

// Constant-time comparison to avoid signature timing oracles.
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8')
  const bb = Buffer.from(b, 'utf8')
  if (ab.length !== bb.length) return false
  return crypto.timingSafeEqual(ab, bb)
}
