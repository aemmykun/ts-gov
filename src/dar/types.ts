import { DocumentStatus } from '../policy/types'
import { Role } from '../identity/roles'
import { Classification, Sensitivity } from '../policy/classification'

// The eligible evidence boundary produced by the DAR. This is a deterministic,
// immutable description of WHAT a user is allowed to retrieve — the input to
// fail-closed retrieval predicates (correction #5).
//
// It is audit-grade: authoritySnapshotId + policyVersion make every boundary
// fully replayable (which assignment set + which policy produced it).
export interface EvidenceBoundary {
  tenantIds:           string[]
  organisationIds:     string[]
  scopeIds:            string[]
  familyIds:           string[]
  // Explicit tenant-wide family access (replaces the '*' magic string).
  allFamilies:         boolean
  allowedStatuses:     DocumentStatus[]
  allowedRoles:        Role[]          // authoritative role(s), NOT claim-derived
  // Clearance ceilings — the highest classification/sensitivity the subject may see.
  classificationLevel: Classification
  sensitivityLevel:    Sensitivity
  // Replay provenance.
  authoritySnapshotId: string         // `${assignmentId}@${assignmentVersion}`
  policyVersion:       string
  effectiveAt:         string
  computedAt:          string
  // True when the subject has no authority at all → retrieval must be refused.
  empty:               boolean
}
