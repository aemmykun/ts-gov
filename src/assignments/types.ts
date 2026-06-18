import { Role } from '../identity/roles'

// Authoritative assignment record (mirrors the SQL `user_assignments` table).
// This is the source of truth for retrieval authority — resolved from the
// assignment store, NEVER from JWT claims.
//
// Canonical hierarchy: tenant → family → child → user. An assignment grants a
// role within a (family[, child]) scope. A NULL childId means the grant covers
// the whole family (family-level access); a non-null childId scopes the grant to
// that single child.
export interface UserAssignment {
  // Replay identity: which exact assignment record (and version) contributed to
  // a DAR decision. Folded into the boundary's authoritySnapshotId.
  assignmentId:      string
  assignmentVersion: string

  userId:    string
  tenantId:  string
  familyId:  string
  childId:   string | null   // null = family-level access
  role:      Role

  // Active window. An assignment with a non-null endedAt is inactive and MUST
  // be ignored by the resolver (fail-closed).
  startedAt: string
  endedAt:   string | null

  source:    string   // e.g. 'hris', 'scim', 'manual-grant'
}

export interface AssignmentResolver {
  // Resolve ALL active assignments for an identity within a tenant. Returns an
  // empty array when the user has no active assignment — callers MUST fail
  // closed (no assignment ⇒ no authority).
  resolve(userId: string, tenantId: string): Promise<UserAssignment[]>
}
