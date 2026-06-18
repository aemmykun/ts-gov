import { EvidenceBoundary } from '../dar/types'
import { PgContext } from './pg'

export interface AuthoritySnapshotRecord {
  tenantId:     string
  snapshotId:   string
  userId:       string
  policyVersion: string
  boundaryHash: string
  boundaryJson: Record<string, unknown>
}

export interface DarDecisionRecord {
  tenantId:            string
  requestId:           string
  userId:              string
  authoritySnapshotId: string
  boundaryHash:        string
  policyVersion:       string
  decision:            'ALLOW' | 'DENY'
}

// Persists DAR replay primitives: the resolved authority snapshot
// (`authority_snapshots`) and the per-request decision (`dar_decisions`) that
// would otherwise vanish after dar.resolve(). Together they let a replay prove
// "why was this allowed/denied?" against the exact governance state.
export class PostgresAuthorityStore {
  constructor(private pg: PgContext) {}

  // Records the snapshot if its (tenant, snapshot_id) is new; idempotent so the
  // same boundary resolving repeatedly does not error.
  async saveSnapshot(rec: AuthoritySnapshotRecord): Promise<void> {
    await this.pg.withTenant({ tenantId: rec.tenantId }, async c => {
      await c.query(
        `INSERT INTO authority_snapshots (
           tenant_id, snapshot_id, user_id, policy_version, boundary_hash, boundary_json
         ) VALUES ($1, $2, $3, $4, $5, $6::jsonb)
         ON CONFLICT (tenant_id, snapshot_id) DO NOTHING`,
        [
          rec.tenantId,
          rec.snapshotId,
          rec.userId,
          rec.policyVersion,
          rec.boundaryHash,
          JSON.stringify(rec.boundaryJson),
        ],
      )
    })
  }

  // Convenience: persist a resolved boundary as a snapshot. boundaryHash is the
  // caller's canonical hash of the boundary (the same value used as the ledger's
  // darDecisionHash), keeping snapshot ↔ decision ↔ ledger linkable.
  async saveBoundary(userId: string, boundary: EvidenceBoundary, boundaryHash: string): Promise<void> {
    await this.saveSnapshot({
      tenantId:     boundary.tenantId,
      snapshotId:   boundary.authoritySnapshotId,
      userId,
      policyVersion: boundary.policyVersion,
      boundaryHash,
      boundaryJson: boundary as unknown as Record<string, unknown>,
    })
  }

  async getSnapshot(tenantId: string, snapshotId: string): Promise<AuthoritySnapshotRecord | null> {
    return this.pg.withTenant({ tenantId }, async c => {
      const res = await c.query<{
        tenant_id: string; snapshot_id: string; user_id: string;
        policy_version: string; boundary_hash: string; boundary_json: Record<string, unknown>
      }>(
        `SELECT tenant_id, snapshot_id, user_id, policy_version, boundary_hash, boundary_json
           FROM authority_snapshots WHERE tenant_id = $1 AND snapshot_id = $2`,
        [tenantId, snapshotId],
      )
      const r = res.rows[0]
      if (!r) return null
      return {
        tenantId: r.tenant_id,
        snapshotId: r.snapshot_id,
        userId: r.user_id,
        policyVersion: r.policy_version,
        boundaryHash: r.boundary_hash,
        boundaryJson: r.boundary_json,
      }
    })
  }

  async saveDecision(rec: DarDecisionRecord): Promise<void> {
    await this.pg.withTenant({ tenantId: rec.tenantId }, async c => {
      await c.query(
        `INSERT INTO dar_decisions (
           tenant_id, request_id, user_id, authority_snapshot_id,
           boundary_hash, policy_version, decision
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          rec.tenantId,
          rec.requestId,
          rec.userId,
          rec.authoritySnapshotId,
          rec.boundaryHash,
          rec.policyVersion,
          rec.decision,
        ],
      )
    })
  }

  async listDecisions(tenantId: string): Promise<DarDecisionRecord[]> {
    return this.pg.withTenant({ tenantId }, async c => {
      const res = await c.query<{
        tenant_id: string; request_id: string; user_id: string;
        authority_snapshot_id: string; boundary_hash: string;
        policy_version: string; decision: 'ALLOW' | 'DENY'
      }>(
        `SELECT tenant_id, request_id, user_id, authority_snapshot_id,
                boundary_hash, policy_version, decision
           FROM dar_decisions WHERE tenant_id = $1 ORDER BY created_at`,
        [tenantId],
      )
      return res.rows.map(r => ({
        tenantId: r.tenant_id,
        requestId: r.request_id,
        userId: r.user_id,
        authoritySnapshotId: r.authority_snapshot_id,
        boundaryHash: r.boundary_hash,
        policyVersion: r.policy_version,
        decision: r.decision,
      }))
    })
  }
}
