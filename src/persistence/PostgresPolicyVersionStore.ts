import { PgContext } from './pg'

export interface PolicyVersionRecord {
  tenantId:    string
  version:     string
  checksum:    string
  publishedBy?: string | null
  publishedAt?: string
}

// Immutable, published policy versions (`policy_versions`). Each version is
// pinned by a checksum so a replay can prove which policy set was in force.
export class PostgresPolicyVersionStore {
  constructor(private pg: PgContext) {}

  // Publishes a new version; (tenant, version) is unique, so re-publishing the
  // same version is a no-op (idempotent).
  async publish(rec: PolicyVersionRecord): Promise<void> {
    await this.pg.withTenant({ tenantId: rec.tenantId }, async c => {
      await c.query(
        `INSERT INTO policy_versions (tenant_id, version, checksum, published_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (tenant_id, version) DO NOTHING`,
        [rec.tenantId, rec.version, rec.checksum, rec.publishedBy ?? null],
      )
    })
  }

  async getLatest(tenantId: string): Promise<PolicyVersionRecord | null> {
    return this.pg.withTenant({ tenantId }, async c => {
      const res = await c.query<{
        tenant_id: string; version: string; checksum: string;
        published_by: string | null; published_at: Date
      }>(
        `SELECT tenant_id, version, checksum, published_by, published_at
           FROM policy_versions WHERE tenant_id = $1
          ORDER BY published_at DESC LIMIT 1`,
        [tenantId],
      )
      const r = res.rows[0]
      if (!r) return null
      return {
        tenantId: r.tenant_id,
        version: r.version,
        checksum: r.checksum,
        publishedBy: r.published_by,
        publishedAt: r.published_at.toISOString(),
      }
    })
  }
}
