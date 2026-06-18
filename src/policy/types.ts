import { TenantClaim } from '../identity/types'
import { Role } from '../identity/roles'

export type DocumentStatus = 'active' | 'quarantined' | 'archived' | 'deleted'

// Authoritative governance policy for a document. Correction #2: every field
// here is sourced from a GovernancePolicyProvider — none of it is defaulted at
// ingestion time.
export interface DocumentPolicy {
  documentId:       string
  tenantId:         string
  familyId:         string
  retainUntil:      Date
  legalHold:        boolean
  legalHoldReason?: string
  allowedRoles:     Role[]
  effectiveFrom:    Date
  effectiveTo:      Date
  status:           DocumentStatus
  classification?:  string
  sensitivity?:     string
}

export interface PolicyContext {
  claim:       TenantClaim
  // Authoritative role resolved from the assignment store (NOT from the claim).
  // Identity establishes who; this establishes authority.
  subjectRole: Role
  document:    DocumentPolicy
  requestedAt: Date
}

export type PolicyGate = 'retention' | 'legal_hold' | 'role_permission' | 'effective_date'

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
