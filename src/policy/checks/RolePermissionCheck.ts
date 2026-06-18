import { PolicyCheck, PolicyContext, PolicyCheckResult } from '../types'
import { roleLevel, requiredLevel } from '../../identity/roles'

export class RolePermissionCheck implements PolicyCheck {
  run(ctx: PolicyContext): PolicyCheckResult {
    const { claim, document } = ctx

    if (claim.role === 'owner') return { passed: true }

    const allowed = document.allowedRoles ?? []

    // Empty allowedRoles must deny everyone (fail-closed). A naive Math.min on
    // an empty list returns Infinity, which previously let ALL roles through.
    const required = requiredLevel(allowed)
    if (!Number.isFinite(required)) {
      return {
        passed:   false,
        failedAt: 'role_permission',
        reason:   'No valid allowedRoles configured — denying access (fail-closed)',
      }
    }

    const subject = roleLevel(claim.role)
    if (subject === 0 || subject < required) {
      return {
        passed:   false,
        failedAt: 'role_permission',
        reason:   `Role '${claim.role}' insufficient for document ${document.documentId}`,
      }
    }

    return { passed: true }
  }
}
