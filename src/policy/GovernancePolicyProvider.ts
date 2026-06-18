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

// Binds governance to a document at ingestion time. If the authoritative
// provider has no policy, ingestion is REFUSED — no default retainUntil /
// effectiveTo / allowedRoles / visibility / legalHold is ever fabricated.
export class IngestionGovernanceBinder {
  constructor(private provider: GovernancePolicyProvider) {}

  async bind(sourceId: string, tenantId: string): Promise<DocumentPolicy> {
    const policy = await this.provider.getPolicy(sourceId, tenantId)
    if (!policy) {
      throw new MissingGovernancePolicyError(sourceId, tenantId)
    }
    return policy
  }
}
