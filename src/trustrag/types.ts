import { GovernedChunk } from '../runtime/ApprovedEvidenceCorpus'
import { ChunkStatus } from '../policy/types'
import { AuthorityScope } from '../dar/types'

// Deterministic predicate compiled from an EvidenceBoundary. Retrieval is
// constrained by this predicate — there is no unrestricted vector search.
export interface RetrievalPredicate {
  tenantId:        string
  scopes:          AuthorityScope[]
  eligibleTopics:  string[]
  allowedStatuses: ChunkStatus[]
  // When true the predicate authorises no retrieval and the index must refuse.
  denyAll:         boolean
}

export interface VectorQuery {
  embedding: number[]
  topK:      number
  predicate: RetrievalPredicate
}

// A vector index implementation MUST honour the predicate. It only ever exposes
// a predicate-scoped search — there is deliberately no "search everything" API.
export interface VectorIndex {
  searchWithin(query: VectorQuery): Promise<GovernedChunk[]>
}
