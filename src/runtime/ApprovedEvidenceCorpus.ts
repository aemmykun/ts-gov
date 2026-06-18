import { TenantClaim } from '../identity/types'
import { Role, roleLevel, roleSatisfies } from '../identity/roles'
import { DocumentStatus } from '../policy/types'
import {
  Classification, Sensitivity, classificationWithin, sensitivityWithin,
} from '../policy/classification'
import { EvidenceBoundary } from '../dar/types'

export type Visibility = 'private' | 'family' | 'tenant' | 'public'

export interface ChunkGovernance {
  status:        DocumentStatus
  allowedRoles:  Role[]
  visibility:    Visibility
  // Correction #3 — additional governance dimensions enforced here too.
  legalHold?:     boolean
  retainUntil?:   string | Date
  effectiveFrom?: string | Date
  effectiveTo?:   string | Date
  classification?: Classification
  sensitivity?:    Sensitivity
  lifecycle?:      'active' | 'superseded' | 'retired' | 'draft'
}

export interface GovernedChunk {
  chunkId:         string
  sourceId:        string
  tenantId:        string
  organisationId?: string
  scopeId?:        string
  familyId:        string
  content:         string
  governance:      ChunkGovernance
}

export interface FilterOptions {
  // Fail-closed strict mode: chunks missing required governance metadata are
  // rejected rather than allowed (correction #2 — no implicit defaults).
  strict?: boolean
  now?:    Date
}

export interface RemovedChunk {
  chunkId: string
  reason:  string
}

export interface CorpusResult {
  chunks:        GovernedChunk[]
  filteredCount: number
  removed:       RemovedChunk[]
}

function toDate(v: string | Date | undefined): Date | null {
  if (v === undefined) return null
  const d = v instanceof Date ? v : new Date(v)
  return Number.isNaN(d.getTime()) ? null : d
}

// The "Ghost Effect": chunks the caller is not authorised to see are removed
// entirely before they ever reach generation. Every removal is fail-closed.
export class ApprovedEvidenceCorpus {
  filter(
    chunks: GovernedChunk[],
    claim: TenantClaim,
    boundary: EvidenceBoundary,
    options: FilterOptions = {},
  ): CorpusResult {
    const now = options.now ?? new Date()
    const strict = options.strict ?? false

    const kept: GovernedChunk[] = []
    const removed: RemovedChunk[] = []

    // No authority at all ⇒ nothing is retrievable.
    if (boundary.empty || boundary.tenantIds.length === 0) {
      return {
        chunks: [],
        filteredCount: chunks.length,
        removed: chunks.map(c => ({ chunkId: c.chunkId, reason: 'no-authority' })),
      }
    }

    const effectiveRole = this.effectiveRole(boundary)

    for (const chunk of chunks) {
      const reason = this.rejectionReason(chunk, effectiveRole, boundary, now, strict)
      if (reason) {
        removed.push({ chunkId: chunk.chunkId, reason })
      } else {
        kept.push(chunk)
      }
    }

    return { chunks: kept, filteredCount: removed.length, removed }
  }

  // Authoritative role = highest role granted by the DAR boundary. NOT the JWT
  // claim role (correction #1).
  private effectiveRole(boundary: EvidenceBoundary): Role | null {
    if (!boundary.allowedRoles || boundary.allowedRoles.length === 0) return null
    return [...boundary.allowedRoles].sort((a, b) => roleLevel(b) - roleLevel(a))[0]
  }

  private rejectionReason(
    chunk: GovernedChunk,
    effectiveRole: Role | null,
    boundary: EvidenceBoundary,
    now: Date,
    strict: boolean,
  ): string | null {
    const g = chunk.governance

    // Tenant isolation.
    if (!boundary.tenantIds.includes(chunk.tenantId)) return 'tenant-mismatch'

    // Organisation membership (enforced when the boundary scopes organisations).
    if (boundary.organisationIds.length > 0) {
      if (chunk.organisationId === undefined) return 'organisation-missing'
      if (!boundary.organisationIds.includes(chunk.organisationId)) return 'organisation-mismatch'
    } else if (strict && chunk.organisationId === undefined) {
      return 'organisation-missing'
    }

    // Scope membership (enforced when the boundary scopes scopes).
    if (boundary.scopeIds.length > 0) {
      if (chunk.scopeId === undefined) return 'scope-missing'
      if (!boundary.scopeIds.includes(chunk.scopeId)) return 'scope-mismatch'
    } else if (strict && chunk.scopeId === undefined) {
      return 'scope-missing'
    }

    // Family / scope membership (tenant-wide for owners via allFamilies).
    if (!boundary.allFamilies && !boundary.familyIds.includes(chunk.familyId)) {
      return 'family-mismatch'
    }

    // Lifecycle status must be within the boundary's allowed statuses.
    if (!boundary.allowedStatuses.includes(g.status)) return 'status-not-allowed'

    // Authoritative role hierarchy.
    if (!effectiveRole) return 'no-authoritative-role'
    if (!roleSatisfies(effectiveRole, g.allowedRoles)) return 'role-insufficient'

    // Legal hold — held evidence is never retrievable.
    if (g.legalHold === true) return 'legal-hold'

    // Retention expiry.
    const retainUntil = toDate(g.retainUntil)
    if (retainUntil) {
      if (retainUntil.getTime() <= now.getTime()) return 'retention-expired'
    } else if (strict) {
      return 'retention-missing'
    }

    // Effective date window.
    const effFrom = toDate(g.effectiveFrom)
    const effTo   = toDate(g.effectiveTo)
    if (effFrom || effTo) {
      if (!effFrom || !effTo) return 'effective-window-incomplete'
      if (effFrom.getTime() > effTo.getTime()) return 'effective-window-integrity'
      if (now.getTime() < effFrom.getTime()) return 'not-yet-effective'
      if (now.getTime() > effTo.getTime()) return 'past-effective'
    } else if (strict) {
      return 'effective-window-missing'
    }

    // Lifecycle (when present) must be an active state.
    if (g.lifecycle !== undefined && g.lifecycle !== 'active') return 'lifecycle-inactive'

    // Classification ceiling.
    if (this.classifiedAbove(g.classification, boundary.classificationLevel, strict)) {
      return 'classification-exceeds-boundary'
    }

    // Sensitivity ceiling.
    if (this.sensitiveAbove(g.sensitivity, boundary.sensitivityLevel, strict)) {
      return 'sensitivity-exceeds-boundary'
    }

    return null
  }

  // Absent metadata is allowed in lenient mode (backward compatible) but rejected
  // in strict mode (correction #2). Present values are tier-compared.
  private classifiedAbove(value: Classification | undefined, ceiling: Classification, strict: boolean): boolean {
    if (value === undefined) return strict
    return !classificationWithin(value, ceiling)
  }

  private sensitiveAbove(value: Sensitivity | undefined, ceiling: Sensitivity, strict: boolean): boolean {
    if (value === undefined) return strict
    return !sensitivityWithin(value, ceiling)
  }
}
