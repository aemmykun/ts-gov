import { TenantClaim } from './types'
import { UserAssignment } from '../assignments/types'

export class TenantIsolationGuard {
  enforce(claim: TenantClaim, requestedTenantId: string): void {
    // Trim/normalise — prevents bypass via ' tenant-A' vs 'tenant-A'.
    const claimed   = claim.tenantId.trim().toLowerCase()
    const requested = (requestedTenantId ?? '').trim().toLowerCase()

    if (!requested) {
      throw new Error('TENANT_ISOLATION: requestedTenantId must not be empty')
    }

    if (claimed !== requested) {
      throw new Error(
        `TENANT_ISOLATION: User ${claim.userId} (tenant: ${claim.tenantId}) ` +
        `attempted cross-tenant access to tenant: ${requestedTenantId}`,
      )
    }
  }

  // Family/child enforcement is driven by the AUTHORITATIVE assignments, never by
  // a claim field. The claim attests identity only; which families/children a
  // user may reach is authority, and authority lives in the assignment store.
  //
  // A family-level assignment (childId === null) authorises the whole family; a
  // child-scoped assignment authorises only that child.
  enforceScope(
    assignments: UserAssignment[],
    requestedFamilyId: string,
    requestedChildId?: string | null,
  ): void {
    const family = (requestedFamilyId ?? '').trim().toLowerCase()
    if (!family) {
      throw new Error('SCOPE_ISOLATION: requestedFamilyId must not be empty')
    }
    const child = (requestedChildId ?? '').trim().toLowerCase() || null

    const ok = assignments.some(a => {
      if (a.familyId.trim().toLowerCase() !== family) return false
      if (a.childId === null) return true            // family-level grant
      if (child === null) return false               // child requested but grant is child-scoped to another child? require match
      return a.childId.trim().toLowerCase() === child
    })

    if (!ok) {
      throw new Error(
        `SCOPE_ISOLATION: Cross-scope access denied — ` +
        `requested family: ${requestedFamilyId}, child: ${requestedChildId ?? 'null'}`,
      )
    }
  }
}
