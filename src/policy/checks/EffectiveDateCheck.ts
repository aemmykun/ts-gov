import { PolicyCheck, PolicyContext, PolicyCheckResult } from '../types'

function isValidDate(d: unknown): d is Date {
  return d instanceof Date && !Number.isNaN(d.getTime())
}

// Effective-date window: a resource is only retrievable once validFrom has been
// reached (the validTo upper bound is enforced by RetentionCheck). An invalid
// validFrom fails closed.
export class EffectiveDateCheck implements PolicyCheck {
  run(ctx: PolicyContext): PolicyCheckResult {
    const { resource, requestedAt } = ctx
    const { validFrom } = resource

    if (!isValidDate(validFrom)) {
      return {
        passed:   false,
        failedAt: 'effective_date',
        reason:   'Resource validFrom is invalid (fail-closed)',
      }
    }

    const now = isValidDate(requestedAt) ? requestedAt : new Date()
    if (now.getTime() < validFrom.getTime()) {
      return {
        passed:   false,
        failedAt: 'effective_date',
        reason:   'Resource is not yet effective',
      }
    }

    return { passed: true }
  }
}
