import { DocumentStatus } from '../policy/types'
import { Role } from '../identity/roles'

// The eligible evidence boundary produced by the DAR. This is a deterministic,
// immutable description of WHAT a user is allowed to retrieve — the input to
// fail-closed retrieval predicates (correction #5).
export interface EvidenceBoundary {
  tenantIds:       string[]
  familyIds:       string[]        // ['*'] means all families within the tenant
  allowedStatuses: DocumentStatus[]
  allowedRoles:    Role[]          // authoritative role(s), NOT claim-derived
  // Highest classification/sensitivity the subject may see (optional tiers).
  maxClassification?: string
  maxSensitivity?:    string
  effectiveAt:     string
  computedAt:      string
  // True when the subject has no authority at all → retrieval must be refused.
  empty?:          boolean
}
