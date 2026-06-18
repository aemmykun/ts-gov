import { AuditLockProvenance, AuditLockRecord, AuditLockSink } from '../policy/AuditLockService'
import { PgContext } from './pg'

interface AuditLockRow {
  resource_id: string
  tenant_id: string
  reason: string
  authority_snapshot_id: string | null
  policy_version: string | null
  boundary_hash: string | null
  locked_at: Date
}

// Persistent audit-lock sink backed by the `audit_locks` table. A legal-hold
// lock is recorded with its governance provenance so an auditor can answer
// "why was this lock raised?" — not merely "was a lock raised?".
export class PostgresAuditLockService implements AuditLockSink {
  constructor(private pg: PgContext) {}

  async lock(
    documentId: string,
    tenantId: string,
    reason: string,
    provenance: AuditLockProvenance = {},
  ): Promise<AuditLockRecord> {
    const row = await this.pg.withTenant({ tenantId }, async c => {
      const res = await c.query<AuditLockRow>(
        `INSERT INTO audit_locks (
           tenant_id, resource_id, reason, authority_snapshot_id, policy_version, boundary_hash
         ) VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING resource_id, tenant_id, reason, authority_snapshot_id,
                   policy_version, boundary_hash, locked_at`,
        [
          tenantId,
          documentId,
          reason,
          provenance.authoritySnapshotId ?? null,
          provenance.policyVersion ?? null,
          provenance.boundaryHash ?? null,
        ],
      )
      return res.rows[0]
    })
    return {
      documentId: row.resource_id,
      tenantId: row.tenant_id,
      reason: row.reason,
      lockedAt: row.locked_at.toISOString(),
      authoritySnapshotId: row.authority_snapshot_id ?? undefined,
      policyVersion: row.policy_version ?? undefined,
      boundaryHash: row.boundary_hash ?? undefined,
    }
  }

  async list(tenantId: string): Promise<AuditLockRecord[]> {
    const rows = await this.pg.withTenant({ tenantId }, async c => {
      const res = await c.query<AuditLockRow>(
        `SELECT resource_id, tenant_id, reason, authority_snapshot_id,
                policy_version, boundary_hash, locked_at
           FROM audit_locks WHERE tenant_id = $1 ORDER BY locked_at`,
        [tenantId],
      )
      return res.rows
    })
    return rows.map(row => ({
      documentId: row.resource_id,
      tenantId: row.tenant_id,
      reason: row.reason,
      lockedAt: row.locked_at.toISOString(),
      authoritySnapshotId: row.authority_snapshot_id ?? undefined,
      policyVersion: row.policy_version ?? undefined,
      boundaryHash: row.boundary_hash ?? undefined,
    }))
  }
}
