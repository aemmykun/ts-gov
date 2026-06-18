import { Classification } from '../policy/classification'
import { GovernancePolicyProvider, SourceGovernance } from '../policy/GovernancePolicyProvider'
import { PgContext } from './pg'

interface SourceRow {
  id: string
  tenant_id: string
  family_id: string | null
  child_id: string | null
  source_type: string
  source_uri: string
  classification: string
  retention_policy_id: string
  legal_hold: boolean
  valid_from: Date
  valid_to: Date | null
  policy_version: string | null
}

// Ingestion governance backed by `rag_sources`. Governance is authoritative:
// the row must already exist (no defaults are fabricated). The governing
// policyVersion is taken from the tenant's latest active `policy_versions` row,
// falling back to 'unversioned' when none is published. policyChecksum is left
// undefined because the base schema stores no attested checksum — when present
// in a record, IngestionGovernanceBinder still verifies it.
export class PostgresGovernancePolicyProvider implements GovernancePolicyProvider {
  constructor(private pg: PgContext) {}

  async getPolicy(sourceId: string, tenantId: string): Promise<SourceGovernance | null> {
    const row = await this.pg.withTenant({ tenantId }, async client => {
      const res = await client.query<SourceRow>(
        `SELECT s.id, s.tenant_id, s.family_id, s.child_id, s.source_type,
                s.source_uri, s.classification, s.retention_policy_id,
                s.legal_hold, s.valid_from, s.valid_to,
                (SELECT pv.version
                   FROM policy_versions pv
                  WHERE pv.tenant_id = s.tenant_id
                  ORDER BY pv.published_at DESC
                  LIMIT 1) AS policy_version
           FROM rag_sources s
          WHERE s.id = $1 AND s.tenant_id = $2`,
        [sourceId, tenantId],
      )
      return res.rows[0] ?? null
    })
    if (!row) return null
    return {
      sourceId: row.id,
      tenantId: row.tenant_id,
      familyId: row.family_id,
      childId: row.child_id,
      sourceType: row.source_type,
      sourceUri: row.source_uri,
      classification: row.classification as Classification,
      retentionPolicyId: row.retention_policy_id,
      legalHold: row.legal_hold,
      validFrom: row.valid_from,
      validTo: row.valid_to,
      policyVersion: row.policy_version ?? 'unversioned',
    }
  }
}
