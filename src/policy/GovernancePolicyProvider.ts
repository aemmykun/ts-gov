import { createHash } from 'crypto'
import { DocumentPolicy } from './types'

// Correction #2: governance metadata (retainUntil, effectiveTo, allowedRoles,
// visibility, legalHold, classification, sensitivity, status) must come from an
// authoritative governance policy — it is NEVER synthesised from defaults
// during ingestion.

export interface GovernancePolicyProvider {
  // Returns the authoritative policy for a source, or null if none is defined.
  getPolicy(sourceId: string, tenantId: string): Promise<DocumentPolicy | null>
}

export class MissingGovernancePolicyError extends Error {
  constructor(sourceId: string, tenantId: string) {
    super(
      `GOVERNANCE: no authoritative policy for source '${sourceId}' in tenant ` +
      `'${tenantId}' — refusing to ingest with defaults (fail-closed)`,
    )
    this.name = 'MissingGovernancePolicyError'
  }
}

export class PolicyIntegrityError extends Error {
  constructor(sourceId: string, tenantId: string) {
    super(
      `GOVERNANCE: policy checksum mismatch for source '${sourceId}' in tenant ` +
      `'${tenantId}' — policy altered after attestation (fail-closed)`,
    )
    this.name = 'PolicyIntegrityError'
  }
}

// Deterministic sha256 over the canonical policy (excluding the checksum field
// itself, with Dates normalised to ISO). Two equal policies always hash equal.
export function computePolicyChecksum(policy: DocumentPolicy): string {
  const canonical = (() => {
    const entries = Object.entries(policy)
      .filter(([k]) => k !== 'policyChecksum')
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => [k, v instanceof Date ? v.toISOString() : v])
    return JSON.stringify(Object.fromEntries(entries))
  })()
  return createHash('sha256').update(canonical).digest('hex')
}

// Binds governance to a document at ingestion time. If the authoritative
// provider has no policy, ingestion is REFUSED — no default retainUntil /
// effectiveTo / allowedRoles / visibility / legalHold is ever fabricated. When
// the policy carries a checksum it is verified, so a tampered policy is rejected.
export class IngestionGovernanceBinder {
  constructor(private provider: GovernancePolicyProvider) {}

  async bind(sourceId: string, tenantId: string): Promise<DocumentPolicy> {
    const policy = await this.provider.getPolicy(sourceId, tenantId)
    if (!policy) {
      throw new MissingGovernancePolicyError(sourceId, tenantId)
    }
    if (policy.policyChecksum && policy.policyChecksum !== computePolicyChecksum(policy)) {
      throw new PolicyIntegrityError(sourceId, tenantId)
    }
    return policy
  }
}
