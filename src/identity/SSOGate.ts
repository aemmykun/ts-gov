import jwt from 'jsonwebtoken'
import jwksClient from 'jwks-rsa'
import { SSOConfig, TenantClaim } from './types'

// QA FIX 1: Pin algorithms — prevents alg:none and HMAC confusion attacks
const ALLOWED_ALGORITHMS: jwt.Algorithm[] = ['RS256', 'RS384', 'RS512']
const MAX_TOKEN_AGE_SECONDS = 3600  // 1 hour hard ceiling
const CLOCK_SKEW_SECONDS    = 60    // tolerate 60s server drift

export class SSOGate {
  private entraClient: jwksClient.JwksClient
  private oktaClient: jwksClient.JwksClient

  constructor(private config: SSOConfig) {
    this.entraClient = jwksClient({
      jwksUri: config.entra.jwksUri,
      cache: true,
      cacheMaxAge: 600_000,
      // QA FIX 2: Rate-limit JWKS fetches — prevents DoS via JWKS hammering
      rateLimit: true,
      jwksRequestsPerMinute: 10
    })
    this.oktaClient = jwksClient({
      jwksUri: config.okta.jwksUri,
      cache: true,
      cacheMaxAge: 600_000,
      rateLimit: true,
      jwksRequestsPerMinute: 10
    })
  }

  async verify(token: string): Promise<TenantClaim> {
    // QA FIX 3: Guard empty/non-string tokens before decode
    if (!token || typeof token !== 'string' || !token.trim()) {
      throw new Error('IDENTITY_GATE: Token must be a non-empty string')
    }

    const decoded = jwt.decode(token, { complete: true })
    if (!decoded || typeof decoded.payload === 'string') {
      throw new Error('IDENTITY_GATE: Invalid token format')
    }

    // QA FIX 4: Reject disallowed algorithms BEFORE JWKS fetch
    if (!ALLOWED_ALGORITHMS.includes(decoded.header.alg as jwt.Algorithm)) {
      throw new Error(
        `IDENTITY_GATE: Algorithm '${decoded.header.alg}' not allowed — must be RS256/RS384/RS512`
      )
    }

    // QA FIX 5: Require kid — JWKS lookup fails silently without it
    if (!decoded.header.kid) {
      throw new Error('IDENTITY_GATE: Token missing kid header')
    }

    const payload = decoded.payload as jwt.JwtPayload

    // QA FIX 6: Enforce max token age independent of exp claim
    if (payload.iat) {
      const ageSeconds = Math.floor(Date.now() / 1000) - payload.iat
      if (ageSeconds > MAX_TOKEN_AGE_SECONDS + CLOCK_SKEW_SECONDS) {
        throw new Error(
          `IDENTITY_GATE: Token too old (${ageSeconds}s) — max ${MAX_TOKEN_AGE_SECONDS}s`
        )
      }
    }

    const issuer = payload.iss ?? ''

    if (issuer.includes('microsoftonline.com')) {
      return this.verifyEntra(token, decoded.header.kid)
    } else if (issuer.includes(this.config.okta.domain)) {
      // QA FIX 7: Match configured okta domain, not generic 'okta.com'
      // — prevents attacker using a DIFFERENT okta tenant to forge tokens
      return this.verifyOkta(token, decoded.header.kid)
    } else {
      throw new Error(`IDENTITY_GATE: Unknown SSO provider '${issuer}' — access denied`)
    }
  }

  private async verifyEntra(token: string, kid: string): Promise<TenantClaim> {
    const key = await this.getSigningKey(this.entraClient, kid)
    const payload = jwt.verify(token, key, {
      audience:       this.config.entra.clientId,
      issuer:         `https://login.microsoftonline.com/${this.config.entra.tenantId}/v2.0`,
      algorithms:     ALLOWED_ALGORITHMS,
      clockTolerance: CLOCK_SKEW_SECONDS
    }) as jwt.JwtPayload

    // QA FIX 8: Validate required claims exist before use
    if (!payload.oid || !payload.tid) {
      throw new Error('IDENTITY_GATE: Entra token missing required claims (oid, tid)')
    }

    // Identity only — authority (role/family/org) is resolved later from the
    // authoritative assignment store, never read from token claims.
    return {
      userId:     payload.oid,
      tenantId:   payload.tid,
      provider:   'entra',
      verifiedAt: Date.now()
    }
  }

  private async verifyOkta(token: string, kid: string): Promise<TenantClaim> {
    const key = await this.getSigningKey(this.oktaClient, kid)
    const payload = jwt.verify(token, key, {
      audience:       this.config.okta.clientId,
      issuer:         `https://${this.config.okta.domain}/oauth2/default`,
      algorithms:     ALLOWED_ALGORITHMS,
      clockTolerance: CLOCK_SKEW_SECONDS
    }) as jwt.JwtPayload

    if (!payload.sub || !payload.tenantId) {
      throw new Error('IDENTITY_GATE: Okta token missing required claims (sub, tenantId)')
    }

    // Identity only — authority is resolved later from the assignment store.
    return {
      userId:     payload.sub,
      tenantId:   payload.tenantId as string,
      provider:   'okta',
      verifiedAt: Date.now()
    }
  }

  private getSigningKey(client: jwksClient.JwksClient, kid: string): Promise<string> {
    return new Promise((resolve, reject) => {
      client.getSigningKey(kid, (err, key) => {
        if (err || !key) {
          reject(new Error(
            `IDENTITY_GATE: Cannot fetch signing key for kid '${kid}' — ${err?.message ?? 'key not found'}`
          ))
        } else {
          resolve(key.getPublicKey())
        }
      })
    })
  }
}
