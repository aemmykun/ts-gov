import { TenantClaim } from './types'
import { UserAssignment } from '../assignments/types'

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

  // Family enforcement is driven by the AUTHORITATIVE assignment, never by a
  // claim field. The claim attests identity only; what families a user may reach
  // is authority, and authority lives in the assignment store.
  enforceFamily(assignment: UserAssignment, requestedFamilyId: string): void {
    // Owner has tenant-wide (all-families) access.
    if (assignment.role === 'owner') return

    const requested = (requestedFamilyId ?? '').trim().toLowerCase()
    if (!requested) {
      throw new Error('FAMILY_ISOLATION: requestedFamilyId must not be empty')
    }

    const granted = assignment.familyIds.map(f => f.trim().toLowerCase())
    if (!granted.includes(requested)) {
      throw new Error(
        `FAMILY_ISOLATION: Cross-family access denied — ` +
        `granted families: [${assignment.familyIds.join(', ')}], requested: ${requestedFamilyId}`
      )
    }
  }
}
