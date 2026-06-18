import { TenantClaim } from './types'

export class TenantIsolationGuard {
  enforce(claim: TenantClaim, requestedTenantId: string): void {
    // QA FIX 1: Trim whitespace — prevents bypass via ' tenant-A' vs 'tenant-A'
    const claimed   = claim.tenantId.trim().toLowerCase()
    const requested = (requestedTenantId ?? '').trim().toLowerCase()

    // QA FIX 2: Reject empty requestedTenantId — was silently passing before
    if (!requested) {
      throw new Error('TENANT_ISOLATION: requestedTenantId must not be empty')
    }

    if (claimed !== requested) {
      throw new Error(
        `TENANT_ISOLATION: User ${claim.userId} (tenant: ${claim.tenantId}) ` +
        `attempted cross-tenant access to tenant: ${requestedTenantId}`
      )
    }
  }

  enforceFamily(claim: TenantClaim, requestedFamilyId: string): void {
    // QA FIX 3: Owner role gets wildcard family access
    if (claim.role === 'owner') return

    const claimed   = claim.familyId.trim().toLowerCase()
    const requested = (requestedFamilyId ?? '').trim().toLowerCase()

    if (!requested) {
      throw new Error('FAMILY_ISOLATION: requestedFamilyId must not be empty')
    }

    if (claimed !== requested) {
      throw new Error(
        `FAMILY_ISOLATION: Cross-family access denied — ` +
        `user family: ${claim.familyId}, requested: ${requestedFamilyId}`
      )
    }
  }
}
