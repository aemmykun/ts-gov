import { ChunkStatus } from '../policy/types'
import { Classification } from '../policy/classification'
import { EvidenceBoundary } from '../dar/types'
import { scopeMatches } from '../dar/scope'

// A governed chunk (mirrors the governance-relevant columns of `rag_chunks`).
export interface GovernedChunk {
  chunkId:        string
  sourceId:       string
  tenantId:       string
  familyId:       string | null   // null = tenant-global
  childId:        string | null   // null = family-level
  topicKey:       string
  status:         ChunkStatus
  legalHold:      boolean
  validFrom:      string | Date
  validTo?:       string | Date | null
  content:        string
  classification?: Classification
  metadata?:      Record<string, unknown>
}

export interface FilterOptions {
  now?: Date
}

export interface RemovedChunk {
  chunkId: string
  reason:  string
}

export interface CorpusResult {
  chunks:        GovernedChunk[]
  filteredCount: number
  removed:       RemovedChunk[]
}

function toDate(v: string | Date | undefined | null): Date | null {
  if (v === undefined || v === null) return null
  const d = v instanceof Date ? v : new Date(v)
  return Number.isNaN(d.getTime()) ? null : d
}

// The canonical governed-retrieval filter (the in-memory analogue of the SQL
// `search_rag_chunks_audited()` enforcement). Chunks the caller is not
// authorised to see are removed entirely before they ever reach generation —
// every removal is fail-closed.
export class ApprovedEvidenceCorpus {
  // Authority is derived entirely from the boundary; no identity claim is read
  // here, so the corpus can never be tricked by a forged claim field.
  filter(
    chunks: GovernedChunk[],
    boundary: EvidenceBoundary,
    options: FilterOptions = {},
  ): CorpusResult {
    const now = options.now ?? new Date()

    // No authority at all ⇒ nothing is retrievable.
    if (boundary.empty || boundary.scopes.length === 0) {
      return {
        chunks: [],
        filteredCount: chunks.length,
        removed: chunks.map(c => ({ chunkId: c.chunkId, reason: 'no-authority' })),
      }
    }

    const kept: GovernedChunk[] = []
    const removed: RemovedChunk[] = []

    for (const chunk of chunks) {
      const reason = this.rejectionReason(chunk, boundary, now)
      if (reason) removed.push({ chunkId: chunk.chunkId, reason })
      else kept.push(chunk)
    }

    return { chunks: kept, filteredCount: removed.length, removed }
  }

  private rejectionReason(
    chunk: GovernedChunk,
    boundary: EvidenceBoundary,
    now: Date,
  ): string | null {
    // Tenant isolation.
    if (chunk.tenantId !== boundary.tenantId) return 'tenant-mismatch'

    // Family / child scope.
    if (!scopeMatches(boundary.scopes, chunk.familyId, chunk.childId)) return 'scope-mismatch'

    // Topic eligibility.
    if (!boundary.eligibleTopics.includes(chunk.topicKey)) return 'topic-not-eligible'

    // Lifecycle status.
    if (!boundary.allowedStatuses.includes(chunk.status)) return 'status-not-allowed'

    // Legal hold — held evidence is never retrievable.
    if (chunk.legalHold === true) return 'legal-hold'

    // Effective window: must be on/after validFrom and before validTo.
    const validFrom = toDate(chunk.validFrom)
    if (!validFrom) return 'effective-window-invalid'
    if (now.getTime() < validFrom.getTime()) return 'not-yet-effective'

    const validTo = toDate(chunk.validTo)
    if (validTo && now.getTime() >= validTo.getTime()) return 'retention-expired'

    return null
  }
}
