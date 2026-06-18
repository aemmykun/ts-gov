import { GovernedChunk } from '../runtime/ApprovedEvidenceCorpus'
import { DocumentStatus } from '../policy/types'
import { Classification, Sensitivity } from '../policy/classification'

// Deterministic predicate compiled from an EvidenceBoundary. Correction #5:
// retrieval is constrained by these predicates — there is no unrestricted
// vector search.
export interface RetrievalPredicate {
  tenantIds:        string[]
  organisationIds:  string[]
  scopeIds:         string[]
  familyIds:        string[]
  allFamilies:      boolean          // tenant-wide family access
  allowedStatuses:  DocumentStatus[]
  allowedRoleNames: string[]
  classificationLevel: Classification
  sensitivityLevel:    Sensitivity
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
