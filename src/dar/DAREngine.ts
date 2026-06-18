import { TenantClaim } from '../identity/types'
import { AssignmentResolver, UserAssignment } from '../assignments/types'
import { InMemoryAssignmentResolver } from '../assignments/InMemoryAssignmentResolver'
import { DocumentStatus } from '../policy/types'
import { EvidenceBoundary } from './types'

export interface DARConfig {
  // Version of the governance policy set in force. Stamped on every boundary so
  // a replay can prove which policy produced it. Inject from your policy store.
  policyVersion?: string
}

// Dynamic Authority Resolver.
//
// Correction #1: authority is resolved from authoritative assignments, never
// from JWT claims. The claim establishes identity (userId/tenantId); the
// assignment store determines role, organisation/scope/family memberships,
// clearance and therefore the evidence boundary.
//
// Correction #5: the boundary is deterministic and immutable so it can be
// compiled into fail-closed retrieval predicates. No assignment ⇒ empty
// boundary ⇒ no retrieval.
//
// Audit-grade: every boundary carries authoritySnapshotId + policyVersion.
export class DAREngine {
  private policyVersion: string

  constructor(
    private assignments: AssignmentResolver = new InMemoryAssignmentResolver(),
    config: DARConfig = {},
  ) {
    this.policyVersion = config.policyVersion ?? 'unversioned'
  }

  async resolve(claim: TenantClaim): Promise<EvidenceBoundary> {
    const nowIso = new Date().toISOString()

    const assignment = await this.assignments.resolve(claim.userId, claim.tenantId)

    // Fail-closed: identity without an authoritative assignment grants nothing.
    if (!assignment) {
      return this.freeze({
        tenantIds:           [],
        organisationIds:     [],
        scopeIds:            [],
        familyIds:           [],
        allFamilies:         false,
        allowedStatuses:     [],
        allowedRoles:        [],
        classificationLevel: 'public',
        sensitivityLevel:    'low',
        authoritySnapshotId: 'none',
        policyVersion:       this.policyVersion,
        effectiveAt:         nowIso,
        computedAt:          nowIso,
        empty:               true,
      })
    }

    const role = assignment.role // authoritative role — claim.role is ignored

    const allFamilies = role === 'owner'
    const allowedStatuses: DocumentStatus[] =
      role === 'owner' || role === 'admin'
        ? ['active', 'quarantined']
        : ['active']

    return this.freeze({
      tenantIds:           [assignment.tenantId],
      organisationIds:     [...assignment.organisationIds],
      scopeIds:            [...assignment.scopeIds],
      familyIds:           allFamilies ? [] : [...assignment.familyIds],
      allFamilies,
      allowedStatuses,
      allowedRoles:        [role],
      classificationLevel: assignment.classificationClearance,
      sensitivityLevel:    assignment.sensitivityClearance,
      authoritySnapshotId: this.snapshotId(assignment),
      policyVersion:       this.policyVersion,
      effectiveAt:         nowIso,
      computedAt:          nowIso,
      empty:               false,
    })
  }

  private snapshotId(a: UserAssignment): string {
    return `${a.assignmentId}@${a.assignmentVersion}`
  }

  private freeze(b: EvidenceBoundary): EvidenceBoundary {
    Object.freeze(b.tenantIds)
    Object.freeze(b.organisationIds)
    Object.freeze(b.scopeIds)
    Object.freeze(b.familyIds)
    Object.freeze(b.allowedStatuses)
    Object.freeze(b.allowedRoles)
    return Object.freeze(b)
  }
}
