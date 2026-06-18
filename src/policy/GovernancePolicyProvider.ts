import { createHash } from 'crypto'
import { Classification } from './classification'

// Authoritative governance for an ingestion source (mirrors `rag_sources`).
// Governance metadata is NEVER synthesised from defaults during ingestion — it
// must come from an authoritative provider.
export interface SourceGovernance {
  sourceId:          string
  tenantId:          string
  familyId:          string | null
  childId:           string | null
  sourceType:        string
  sourceUri:         string
  classification:    Classification
  retentionPolicyId: string
  legalHold:         boolean
  validFrom:         Date
  validTo:           Date | null
  // Version of the governing policy set (proves WHICH policy authorised ingestion).
  policyVersion:     string
  // Optional integrity anchor: sha256 of the canonical governance record.
  policyChecksum?:   string
}

export interface GovernancePolicyProvider {
  // Returns the authoritative governance for a source, or null if none exists.
  getPolicy(sourceId: string, tenantId: string): Promise<SourceGovernance | null>
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

// Deterministic sha256 over the canonical governance record (excluding the
// checksum field itself, with Dates normalised to ISO). Two equal records always
// hash equal.
export function computePolicyChecksum(policy: SourceGovernance): string {
  const entries = Object.entries(policy)
    .filter(([k]) => k !== 'policyChecksum')
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => [k, v instanceof Date ? v.toISOString() : v])
  return createHash('sha256').update(JSON.stringify(Object.fromEntries(entries))).digest('hex')
}

// Binds governance to a source at ingestion time. If the authoritative provider
// has no policy, ingestion is REFUSED — no defaults are ever fabricated. When the
// policy carries a checksum it is verified, so a tampered policy is rejected.
export class IngestionGovernanceBinder {
  constructor(private provider: GovernancePolicyProvider) {}

  async bind(sourceId: string, tenantId: string): Promise<SourceGovernance> {
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
