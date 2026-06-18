import { PolicyCheck, PolicyContext, PolicyCheckResult } from '../types'

// Tenant isolation at the resource level: a resource from another tenant is
// never retrievable, regardless of any other grant.
export class TenantBoundaryCheck implements PolicyCheck {
  run(ctx: PolicyContext): PolicyCheckResult {
    if (ctx.resource.tenantId !== ctx.boundary.tenantId) {
      return {
        passed:   false,
        failedAt: 'tenant_boundary',
        reason:   `Resource tenant '${ctx.resource.tenantId}' is outside boundary tenant '${ctx.boundary.tenantId}'`,
      }
    }
    return { passed: true }
  }
}
