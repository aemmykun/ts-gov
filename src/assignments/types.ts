import { Role } from '../identity/roles'

// Authoritative assignment record. This is the source of truth for retrieval
// authority — resolved from the user-assignment / membership store, NEVER from
// JWT claims. Correction #1:
//   user → user_assignments → organisation/scope memberships → DAR
export interface UserAssignment {
  userId:        string
  tenantId:      string
  // Family / scope memberships the user is authoritatively granted.
  familyIds:     string[]
  scopeIds:      string[]
  // Authoritative role grant within the tenant.
  role:          Role
  // Provenance for audit/replay.
  source:        string   // e.g. 'hris', 'scim', 'manual-grant'
  assignedAt:    string
}

export interface AssignmentResolver {
  // Resolve the authoritative assignment for an identity. Returns null when the
  // user has no assignment in the tenant — callers MUST fail closed.
  resolve(userId: string, tenantId: string): Promise<UserAssignment | null>
}
