import { EvidenceBoundary } from '../dar/types'
import { ApprovedEvidenceCorpus, GovernedChunk, FilterOptions } from '../runtime/ApprovedEvidenceCorpus'
import { TenantClaim } from '../identity/types'
import { RetrievalPredicate, VectorIndex } from './types'

export class UnauthorizedRetrievalError extends Error {
  constructor() {
    super('TRUSTRAG: empty evidence boundary — retrieval refused (fail-closed)')
    this.name = 'UnauthorizedRetrievalError'
  }
}

export interface RetrievalResult {
  chunks:        GovernedChunk[]
  predicate:     RetrievalPredicate
  filteredCount: number
}

// Governed retrieval. Correction #5:
//  - the DAR boundary is compiled into a deterministic predicate;
//  - an empty boundary fails closed (no search is performed);
//  - the index is only ever queried *within* the predicate — never unrestricted;
//  - results are passed through the ApprovedEvidenceCorpus as defence in depth.
export class TrustRAGRetriever {
  private corpus = new ApprovedEvidenceCorpus()

  constructor(private index: VectorIndex) {}

  // Pure, deterministic compilation of authority → predicate.
  compilePredicate(boundary: EvidenceBoundary): RetrievalPredicate {
    const denyAll = Boolean(boundary.empty) || boundary.tenantIds.length === 0
    return {
      tenantIds:         [...boundary.tenantIds],
      familyIds:         [...boundary.familyIds],
      allowedStatuses:   [...boundary.allowedStatuses],
      allowedRoleNames:  [...boundary.allowedRoles],
      maxClassification: boundary.maxClassification,
      maxSensitivity:    boundary.maxSensitivity,
      denyAll,
    }
  }

  async retrieve(
    embedding: number[],
    topK: number,
    claim: TenantClaim,
    boundary: EvidenceBoundary,
    options: FilterOptions = {},
  ): Promise<RetrievalResult> {
    const predicate = this.compilePredicate(boundary)

    // Fail-closed: never call the index without authority.
    if (predicate.denyAll) {
      throw new UnauthorizedRetrievalError()
    }

    const raw = await this.index.searchWithin({ embedding, topK, predicate })

    // Defence in depth: even predicate-scoped results are re-checked.
    const result = this.corpus.filter(raw, claim, boundary, options)

    return {
      chunks:        result.chunks,
      predicate,
      filteredCount: result.filteredCount,
    }
  }
}
