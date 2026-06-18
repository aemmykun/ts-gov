import { HandOffManifest } from '../handoff/types'
import { PgContext } from './pg'

// Persists evidence-integrity manifests (`handoff_manifests`): source/chunk
// hashes, the HMAC signature, ingestion audit and chain-of-custody. The full
// manifest body (incl. chunkIds, custody events) is kept in jsonb columns so a
// stored manifest can be re-verified later by HandOffVerifier.
export class PostgresHandoffStore {
  constructor(private pg: PgContext) {}

  async save(tenantId: string, manifest: HandOffManifest): Promise<void> {
    await this.pg.withTenant({ tenantId }, async c => {
      await c.query(
        `INSERT INTO handoff_manifests (
           tenant_id, source_id, source_hash, chunk_hash, signature, key_id,
           ingestion_audit, chain_of_custody
         ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb)`,
        [
          tenantId,
          manifest.sourceId,
          manifest.sourceHash,
          manifest.chunkHash,
          manifest.signature,
          manifest.keyId,
          JSON.stringify({
            ...manifest.ingestionAudit,
            chunkIds: manifest.chunkIds,
            manifestHash: manifest.manifestHash,
            signedAt: manifest.signedAt,
          }),
          JSON.stringify(manifest.chainOfCustody),
        ],
      )
    })
  }

  async countForSource(tenantId: string, sourceId: string): Promise<number> {
    return this.pg.withTenant({ tenantId }, async c => {
      const res = await c.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM handoff_manifests
          WHERE tenant_id = $1 AND source_id = $2`,
        [tenantId, sourceId],
      )
      return Number(res.rows[0].count)
    })
  }
}
