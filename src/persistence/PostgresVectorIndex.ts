import { Classification } from '../policy/classification'
import { ChunkStatus } from '../policy/types'
import { GovernedChunk } from '../runtime/ApprovedEvidenceCorpus'
import { VectorIndex, VectorQuery } from '../trustrag/types'
import { PgContext, toVectorLiteral } from './pg'

interface ChunkRow {
  id: string
  source_id: string
  tenant_id: string
  family_id: string | null
  child_id: string | null
  topic_key: string
  status: string
  legal_hold: boolean
  valid_from: Date
  valid_to: Date | null
  chunk_text: string
  classification: string | null
  metadata: Record<string, unknown>
}

// pgvector-backed implementation of the canonical governed-retrieval enforcement
// point (SQL search_rag_chunks_audited()). It NEVER exposes an unrestricted
// search: every query is constrained by the compiled predicate — tenant, the
// family/child scope chain, eligible topics, allowed statuses, legal hold and
// the validity window — and ordered by vector distance. Tenant isolation is also
// enforced underneath by RLS (app.tenant_id); scope filtering is done in-query
// because a boundary may hold multiple scopes (more than the single app.family_id
// GUC can express). The TrustRAG corpus re-applies every gate as defence in depth.
export class PostgresVectorIndex implements VectorIndex {
  constructor(private pg: PgContext) {}

  async searchWithin(query: VectorQuery): Promise<GovernedChunk[]> {
    const { predicate, embedding, topK } = query
    if (predicate.denyAll) return []

    const scopesJson = JSON.stringify(
      predicate.scopes.map(s => ({ family_id: s.familyId, child_id: s.childId })),
    )

    const rows = await this.pg.withTenant({ tenantId: predicate.tenantId }, async c => {
      const res = await c.query<ChunkRow>(
        `SELECT ch.id, ch.source_id, ch.tenant_id, ch.family_id, ch.child_id,
                ch.topic_key, ch.status, ch.legal_hold, ch.valid_from, ch.valid_to,
                ch.chunk_text, s.classification, ch.metadata
           FROM rag_chunks ch
           LEFT JOIN rag_sources s
             ON s.tenant_id = ch.tenant_id AND s.id = ch.source_id
          WHERE ch.tenant_id = $1
            AND ch.topic_key = ANY($2::text[])
            AND ch.status = ANY($3::text[])
            AND ch.legal_hold = false
            AND ch.valid_from <= now()
            AND (ch.valid_to IS NULL OR ch.valid_to > now())
            AND (
              ch.family_id IS NULL
              OR EXISTS (
                SELECT 1
                  FROM jsonb_to_recordset($4::jsonb) AS sc(family_id uuid, child_id uuid)
                 WHERE sc.family_id = ch.family_id
                   AND (sc.child_id IS NULL OR ch.child_id IS NULL OR sc.child_id = ch.child_id)
              )
            )
          ORDER BY ch.embedding <=> $5::vector
          LIMIT $6`,
        [
          predicate.tenantId,
          predicate.eligibleTopics,
          predicate.allowedStatuses,
          scopesJson,
          toVectorLiteral(embedding),
          topK,
        ],
      )
      return res.rows
    })

    return rows.map(r => ({
      chunkId: r.id,
      sourceId: r.source_id,
      tenantId: r.tenant_id,
      familyId: r.family_id,
      childId: r.child_id,
      topicKey: r.topic_key,
      status: r.status as ChunkStatus,
      legalHold: r.legal_hold,
      validFrom: r.valid_from,
      validTo: r.valid_to,
      content: r.chunk_text,
      classification: (r.classification as Classification | null) ?? undefined,
      metadata: r.metadata,
    }))
  }
}
