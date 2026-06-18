import { Role } from '../identity/roles'
import { Classification, Sensitivity } from '../policy/classification'

// Authoritative assignment record. This is the source of truth for retrieval
// authority — resolved from the user-assignment / membership store, NEVER from
// JWT claims. Correction #1:
//   user → user_assignments → organisation/scope memberships → DAR
export interface UserAssignment {
  // Replay identity: which exact assignment record (and version) produced a
  // DAR decision. Stamped onto the boundary as authoritySnapshotId.
  assignmentId:      string
  assignmentVersion: string

  userId:        string
  tenantId:      string
  // Organisation / scope / family memberships the user is authoritatively
  // granted (tenant → organisation → scope → family).
  organisationIds: string[]
  scopeIds:        string[]
  familyIds:       string[]
  // Authoritative role grant within the tenant.
  role:          Role
  // Authoritative clearance ceilings.
  classificationClearance: Classification
  sensitivityClearance:    Sensitivity
  // Provenance for audit/replay.
  source:        string   // e.g. 'hris', 'scim', 'manual-grant'
  assignedAt:    string
}

export interface AssignmentResolver {
  // Resolve the authoritative assignment for an identity. Returns null when the
  // user has no assignment in the tenant — callers MUST fail closed.
  resolve(userId: string, tenantId: string): Promise<UserAssignment | null>
}
