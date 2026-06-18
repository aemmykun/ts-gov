import { TenantClaim } from '../identity/types'
import { Classification } from './classification'
import { EvidenceBoundary } from '../dar/types'

// Chunk lifecycle status (mirrors the SQL `rag_chunks.status` check constraint).
// Only ACTIVE chunks are ever retrievable.
export type ChunkStatus = 'ACTIVE' | 'REVOKED' | 'EXPIRED'

// A governed resource (chunk or source) evaluated against an authority boundary.
// Mirrors the governance-relevant columns of `rag_chunks` / `rag_sources`.
export interface PolicyResource {
  resourceId:       string          // chunkId (or sourceId)
  tenantId:         string
  familyId:         string | null   // null = tenant/family-wide
  childId:          string | null   // null = family-level
  topicKey:         string
  status:           ChunkStatus
  legalHold:        boolean
  legalHoldReason?: string
  validFrom:        Date
  validTo?:         Date | null
  classification?:  Classification
  policyVersion:    string          // version of the governing policy set
}

export interface PolicyContext {
  claim:       TenantClaim
  // Authority surface resolved by the DAR (scopes + eligible topics). Identity
  // establishes who; the boundary establishes what may be reached.
  boundary:    EvidenceBoundary
  resource:    PolicyResource
  requestedAt: Date
  // Audit-grade replay provenance stamped onto any governance event (e.g. a
  // legal-hold audit lock) so it proves *why* it fired.
  provenance?: {
    authoritySnapshotId?: string
    policyVersion?:       string
    boundaryHash?:        string
    ruleVersion?:         string
  }
}

// Ordered governance gates (closest to the canonical DAR flow:
// tenant → scope → topic → status → legal hold → retention → effective date).
export type PolicyGate =
  | 'tenant_boundary'
  | 'scope'
  | 'topic_permission'
  | 'status'
  | 'legal_hold'
  | 'retention'
  | 'effective_date'

export interface PolicyCheckResult {
  passed:       boolean
  failedAt?:    PolicyGate
  reason?:      string
  // Set when a legal-hold violation must lock the audit trail for compliance.
  auditLocked?: boolean
}

export interface PolicyCheck {
  run(ctx: PolicyContext): PolicyCheckResult
}
