import { TenantClaim } from '../identity/types'
import { Role, roleLevel, roleSatisfies } from '../identity/roles'
import { DocumentStatus } from '../policy/types'
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
  classification?: string
  sensitivity?:    string
  lifecycle?:      'active' | 'superseded' | 'retired' | 'draft'
}

export interface GovernedChunk {
  chunkId:    string
  sourceId:   string
  tenantId:   string
  familyId:   string
  content:    string
  governance: ChunkGovernance
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

// Ordered classification / sensitivity tiers (low → high). Unknown tiers are
// treated as maximally sensitive (fail-closed).
const CLASSIFICATION_ORDER = ['public', 'internal', 'confidential', 'restricted']
const SENSITIVITY_ORDER    = ['low', 'medium', 'high', 'critical']

function tierIndex(order: string[], value: string | undefined): number {
  if (!value) return order.length // unknown ⇒ most sensitive
  const i = order.indexOf(value.toLowerCase())
  return i === -1 ? order.length : i
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

    // Family / scope membership (wildcard for owners).
    if (!boundary.familyIds.includes('*') && !boundary.familyIds.includes(chunk.familyId)) {
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

    // Classification / sensitivity ceilings (when the boundary defines them).
    if (boundary.maxClassification) {
      if (tierIndex(CLASSIFICATION_ORDER, g.classification) >
          tierIndex(CLASSIFICATION_ORDER, boundary.maxClassification)) {
        return 'classification-exceeds-boundary'
      }
    } else if (strict && g.classification === undefined) {
      return 'classification-missing'
    }

    if (boundary.maxSensitivity) {
      if (tierIndex(SENSITIVITY_ORDER, g.sensitivity) >
          tierIndex(SENSITIVITY_ORDER, boundary.maxSensitivity)) {
        return 'sensitivity-exceeds-boundary'
      }
    } else if (strict && g.sensitivity === undefined) {
      return 'sensitivity-missing'
    }

    return null
  }
}
