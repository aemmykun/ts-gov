import { PolicyCheck, PolicyContext, PolicyCheckResult } from '../types'

// Lifecycle status: only statuses in the boundary's allowedStatuses (canonically
// ['ACTIVE']) are retrievable. REVOKED / EXPIRED chunks are never returned.
export class StatusCheck implements PolicyCheck {
  run(ctx: PolicyContext): PolicyCheckResult {
    const { resource, boundary } = ctx
    if (!boundary.allowedStatuses.includes(resource.status)) {
      return {
        passed:   false,
        failedAt: 'status',
        reason:   `Resource status '${resource.status}' is not retrievable`,
      }
    }
    return { passed: true }
  }
}
