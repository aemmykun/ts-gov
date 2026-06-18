import { ChunkStatus } from '../policy/types'

// A single authority scope granted to the subject: a family, optionally narrowed
// to one child. childId === null means family-level access (the whole family).
export interface AuthorityScope {
  familyId: string
  childId:  string | null
}

// The eligible evidence boundary produced by the DAR. A deterministic, immutable
// description of WHAT a user is allowed to retrieve — the input to fail-closed
// retrieval predicates.
//
// Canonical model: authority is the union of the subject's assignment scopes
// (family/child) intersected with the topics their role(s) are permitted via the
// `policies` table. It is audit-grade: authoritySnapshotId + policyVersion make
// every boundary fully replayable (which assignment set + which policy produced it).
export interface EvidenceBoundary {
  tenantId:        string
  // Family/child scopes from the subject's active assignments.
  scopes:          AuthorityScope[]
  // Union of allowed_topics across the subject's role(s). Evidence is reachable
  // only when its topic_key is in this set.
  eligibleTopics:  string[]
  // Retrievable lifecycle statuses — always ['ACTIVE'] in the canonical model.
  allowedStatuses: ChunkStatus[]
  // Highest role level among the subject's assignments (coarse privilege only).
  roleLevel:       number
  // Replay provenance.
  authoritySnapshotId: string   // hash of the contributing assignment set + versions
  policyVersion:       string   // version(s) of the topic policies applied
  effectiveAt:         string
  computedAt:          string
  // True when the subject has no authority at all → retrieval must be refused.
  empty:               boolean
}
