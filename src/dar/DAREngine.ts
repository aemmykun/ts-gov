import crypto from 'crypto'
import { TenantClaim } from '../identity/types'
import { AssignmentResolver, UserAssignment } from '../assignments/types'
import { InMemoryAssignmentResolver } from '../assignments/InMemoryAssignmentResolver'
import { TopicPolicyProvider, InMemoryTopicPolicyProvider } from '../policy/TopicPolicyProvider'
import { roleLevel } from '../identity/roles'
import { AuthorityScope, EvidenceBoundary } from './types'

export interface DARConfig {
  // Fallback policy version stamped when no topic policy contributes one.
  policyVersion?: string
}

// Dynamic Authority Resolver.
//
// Authority is resolved from authoritative assignments + topic policies, never
// from JWT claims. The claim establishes identity (userId/tenantId); the
// assignment store determines the family/child scopes and role(s), and the
// policies table determines which topics those role(s) may retrieve.
//
// The boundary is deterministic and immutable so it can be compiled into
// fail-closed retrieval predicates. No assignment ⇒ empty boundary ⇒ no
// retrieval. Every boundary carries authoritySnapshotId + policyVersion.
export class DAREngine {
  private fallbackPolicyVersion: string

  constructor(
    private assignments: AssignmentResolver = new InMemoryAssignmentResolver(),
    private topics: TopicPolicyProvider = new InMemoryTopicPolicyProvider(),
    config: DARConfig = {},
  ) {
    this.fallbackPolicyVersion = config.policyVersion ?? 'unversioned'
  }

  async resolve(claim: TenantClaim): Promise<EvidenceBoundary> {
    const nowIso = new Date().toISOString()
    const assignments = await this.assignments.resolve(claim.userId, claim.tenantId)

    // Fail-closed: identity without any active assignment grants nothing.
    if (assignments.length === 0) {
      return this.freeze({
        tenantId:            claim.tenantId,
        scopes:              [],
        eligibleTopics:      [],
        allowedStatuses:     [],
        roleLevel:           0,
        authoritySnapshotId: 'none',
        policyVersion:       this.fallbackPolicyVersion,
        effectiveAt:         nowIso,
        computedAt:          nowIso,
        empty:               true,
      })
    }

    const scopes = this.dedupeScopes(
      assignments.map(a => ({ familyId: a.familyId, childId: a.childId ?? null })),
    )

    // Topic eligibility = union of allowed_topics over the distinct roles held.
    const roles = [...new Set(assignments.map(a => a.role))]
    const topicSet = new Set<string>()
    const versions = new Set<string>()
    for (const role of roles) {
      const policy = await this.topics.getPolicy(claim.tenantId, role)
      if (!policy) continue
      for (const t of policy.allowedTopics) topicSet.add(t)
      versions.add(policy.version)
    }

    const maxRoleLevel = Math.max(...assignments.map(a => roleLevel(a.role)))
    const policyVersion = versions.size > 0
      ? [...versions].sort().join(',')
      : this.fallbackPolicyVersion

    return this.freeze({
      tenantId:            claim.tenantId,
      scopes,
      eligibleTopics:      [...topicSet].sort(),
      allowedStatuses:     ['ACTIVE'],
      roleLevel:           maxRoleLevel,
      authoritySnapshotId: this.snapshotId(assignments),
      policyVersion,
      effectiveAt:         nowIso,
      computedAt:          nowIso,
      empty:               false,
    })
  }

  private dedupeScopes(scopes: AuthorityScope[]): AuthorityScope[] {
    const seen = new Map<string, AuthorityScope>()
    for (const s of scopes) seen.set(`${s.familyId}::${s.childId ?? ''}`, s)
    return [...seen.values()].sort((a, b) =>
      `${a.familyId}${a.childId ?? ''}`.localeCompare(`${b.familyId}${b.childId ?? ''}`),
    )
  }

  // Deterministic hash over the contributing assignment identities + versions,
  // so a replay can prove exactly which authority set produced the boundary.
  private snapshotId(assignments: UserAssignment[]): string {
    const ids = assignments
      .map(a => `${a.assignmentId}@${a.assignmentVersion}`)
      .sort()
    return crypto.createHash('sha256').update(ids.join('|'), 'utf8').digest('hex')
  }

  private freeze(b: EvidenceBoundary): EvidenceBoundary {
    b.scopes.forEach(s => Object.freeze(s))
    Object.freeze(b.scopes)
    Object.freeze(b.eligibleTopics)
    Object.freeze(b.allowedStatuses)
    return Object.freeze(b)
  }
}
