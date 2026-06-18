import { PoolClient } from 'pg'
import { LedgerStore } from '../ledger/LedgerStore'
import { EvidenceBlock } from '../ledger/types'
import { HandOffManifest } from '../handoff/types'
import { PgContext } from './pg'

interface LedgerRow {
  id: string
  block_number: string
  request_id: string
  tenant_id: string
  created_at: Date
  decision: string
  dar_decision_hash: string
  retrieved_evidence_ids: string[]
  prompt_hash: string | null
  response_hash: string | null
  ai_output: EvidenceBlock['aiOutput']
  handoff: HandOffManifest | null
  authority_snapshot_id: string | null
  policy_version: string | null
  boundary_hash: string | null
  user_identity: EvidenceBlock['userIdentity']
  data_json: Record<string, unknown>
  previous_hash: string | null
  current_hash: string
  next_hash: string | null
}

function rowToBlock(r: LedgerRow): EvidenceBlock {
  const authority =
    r.authority_snapshot_id !== null && r.policy_version !== null && r.boundary_hash !== null
      ? {
          authoritySnapshotId: r.authority_snapshot_id,
          policyVersion: r.policy_version,
          boundaryHash: r.boundary_hash,
        }
      : null
  return {
    blockId: r.id,
    requestId: r.request_id,
    blockNumber: Number(r.block_number),
    tenantId: r.tenant_id,
    createdAt: r.created_at.toISOString(),
    decision: r.decision as 'ALLOW' | 'DENY',
    darDecisionHash: r.dar_decision_hash,
    userIdentity: r.user_identity,
    retrievedEvidenceIds: r.retrieved_evidence_ids,
    promptHash: r.prompt_hash,
    responseHash: r.response_hash,
    aiOutput: r.ai_output,
    handoff: r.handoff ?? undefined,
    authority,
    dataJson: r.data_json,
    auditTrail: {
      previousHash: r.previous_hash ?? 'GENESIS',
      currentHash: r.current_hash,
      nextHash: r.next_hash,
    },
  }
}

const SELECT_COLS = `
  id, block_number, request_id, tenant_id, created_at, decision, dar_decision_hash,
  retrieved_evidence_ids, prompt_hash, response_hash, ai_output, handoff,
  authority_snapshot_id, policy_version, boundary_hash, user_identity, data_json,
  previous_hash, current_hash, next_hash`

// Evidence ledger backed by the `evidence_ledger` table. Append-only,
// hash-chained, tenant-scoped under RLS. The richer block fields (user identity,
// AI output, handoff manifest) are persisted as jsonb; the queryable
// chain/replay fields are first-class columns.
export class PostgresLedgerStore implements LedgerStore {
  constructor(private pg: PgContext) {}

  private query<T>(tenantId: string, fn: (c: PoolClient) => Promise<T>): Promise<T> {
    return this.pg.withTenant({ tenantId }, fn)
  }

  async getLatest(tenantId: string): Promise<EvidenceBlock | null> {
    return this.query(tenantId, async c => {
      const res = await c.query<LedgerRow>(
        `SELECT ${SELECT_COLS} FROM evidence_ledger
          WHERE tenant_id = $1 ORDER BY block_number DESC LIMIT 1`,
        [tenantId],
      )
      return res.rows[0] ? rowToBlock(res.rows[0]) : null
    })
  }

  async append(block: EvidenceBlock): Promise<void> {
    await this.query(block.tenantId, async c => {
      await c.query(
        `INSERT INTO evidence_ledger (
           tenant_id, id, block_number, request_id, created_at, decision,
           dar_decision_hash, retrieved_evidence_ids, prompt_hash, response_hash,
           ai_output, handoff, authority_snapshot_id, policy_version, boundary_hash,
           user_identity, data_json, previous_hash, current_hash, next_hash
         ) VALUES (
           $1, $2, $3, $4, $5, $6,
           $7, $8::uuid[], $9, $10,
           $11::jsonb, $12::jsonb, $13, $14, $15,
           $16::jsonb, $17::jsonb, $18, $19, $20
         )`,
        [
          block.tenantId,
          block.blockId,
          block.blockNumber,
          block.requestId,
          block.createdAt,
          block.decision,
          block.darDecisionHash,
          block.retrievedEvidenceIds,
          block.promptHash,
          block.responseHash,
          block.aiOutput ? JSON.stringify(block.aiOutput) : null,
          block.handoff ? JSON.stringify(block.handoff) : null,
          block.authority?.authoritySnapshotId ?? null,
          block.authority?.policyVersion ?? null,
          block.authority?.boundaryHash ?? null,
          JSON.stringify(block.userIdentity),
          JSON.stringify(block.dataJson),
          block.auditTrail.previousHash === 'GENESIS' ? null : block.auditTrail.previousHash,
          block.auditTrail.currentHash,
          block.auditTrail.nextHash,
        ],
      )
    })
  }

  async updateNextHash(tenantId: string, blockId: string, nextHash: string): Promise<void> {
    await this.query(tenantId, async c => {
      const res = await c.query(
        `UPDATE evidence_ledger SET next_hash = $3 WHERE tenant_id = $1 AND id = $2`,
        [tenantId, blockId, nextHash],
      )
      if (res.rowCount === 0) {
        throw new Error(`LEDGER_STORE: block ${blockId} not found for updateNextHash`)
      }
    })
  }

  async getRange(tenantId: string, from: number, to: number): Promise<EvidenceBlock[]> {
    return this.query(tenantId, async c => {
      const res = await c.query<LedgerRow>(
        `SELECT ${SELECT_COLS} FROM evidence_ledger
          WHERE tenant_id = $1 AND block_number >= $2 AND block_number <= $3
          ORDER BY block_number`,
        [tenantId, from, to],
      )
      return res.rows.map(rowToBlock)
    })
  }

  async getByNumber(tenantId: string, blockNumber: number): Promise<EvidenceBlock | null> {
    return this.query(tenantId, async c => {
      const res = await c.query<LedgerRow>(
        `SELECT ${SELECT_COLS} FROM evidence_ledger
          WHERE tenant_id = $1 AND block_number = $2`,
        [tenantId, blockNumber],
      )
      return res.rows[0] ? rowToBlock(res.rows[0]) : null
    })
  }
}
