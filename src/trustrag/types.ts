import { GovernedChunk } from '../runtime/ApprovedEvidenceCorpus'
import { DocumentStatus } from '../policy/types'

// Deterministic predicate compiled from an EvidenceBoundary. Correction #5:
// retrieval is constrained by these predicates — there is no unrestricted
// vector search.
export interface RetrievalPredicate {
  tenantIds:        string[]
  familyIds:        string[]        // ['*'] ⇒ all families within tenant
  allowedStatuses:  DocumentStatus[]
  allowedRoleNames: string[]
  maxClassification?: string
  maxSensitivity?:    string
  // When true the predicate authorises no retrieval and the index must refuse.
  denyAll:          boolean
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
