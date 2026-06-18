import { TenantClaim } from '../identity/types'
import { AssignmentResolver } from '../assignments/types'
import { InMemoryAssignmentResolver } from '../assignments/InMemoryAssignmentResolver'
import { DocumentStatus } from '../policy/types'
import { EvidenceBoundary } from './types'

// Dynamic Authority Resolver.
//
// Correction #1: authority is resolved from authoritative assignments, never
// from JWT claims. The claim establishes identity (userId/tenantId); the
// assignment store determines the role, family/scope memberships and therefore
// the evidence boundary.
//
// Correction #5: the boundary is deterministic and immutable so it can be
// compiled into fail-closed retrieval predicates. No assignment ⇒ empty
// boundary ⇒ no retrieval.
export class DAREngine {
  constructor(
    private assignments: AssignmentResolver = new InMemoryAssignmentResolver(),
  ) {}

  async resolve(claim: TenantClaim): Promise<EvidenceBoundary> {
    const nowIso = new Date().toISOString()

    const assignment = await this.assignments.resolve(claim.userId, claim.tenantId)

    // Fail-closed: identity without an authoritative assignment grants nothing.
    if (!assignment) {
      return this.freeze({
        tenantIds:       [],
        familyIds:       [],
        allowedStatuses: [],
        allowedRoles:    [],
        effectiveAt:     nowIso,
        computedAt:      nowIso,
        empty:           true,
      })
    }

    const role = assignment.role // authoritative role — claim.role is ignored

    const familyIds = role === 'owner' ? ['*'] : [...assignment.familyIds]

    const allowedStatuses: DocumentStatus[] =
      role === 'owner' || role === 'admin'
        ? ['active', 'quarantined']
        : ['active']

    return this.freeze({
      tenantIds:       [assignment.tenantId],
      familyIds,
      allowedStatuses,
      allowedRoles:    [role],
      effectiveAt:     nowIso,
      computedAt:      nowIso,
      empty:           false,
    })
  }

  private freeze(b: EvidenceBoundary): EvidenceBoundary {
    Object.freeze(b.tenantIds)
    Object.freeze(b.familyIds)
    Object.freeze(b.allowedStatuses)
    Object.freeze(b.allowedRoles)
    return Object.freeze(b)
  }
}
