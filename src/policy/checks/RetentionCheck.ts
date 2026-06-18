import { PolicyCheck, PolicyContext, PolicyCheckResult } from '../types'

function isValidDate(d: unknown): d is Date {
  return d instanceof Date && !Number.isNaN(d.getTime())
}

export class RetentionCheck implements PolicyCheck {
  run(ctx: PolicyContext): PolicyCheckResult {
    const { document, requestedAt } = ctx
    const retainUntil = document.retainUntil

    // Fail-closed: missing or invalid retention metadata is never trusted.
    if (!isValidDate(retainUntil)) {
      return {
        passed:   false,
        failedAt: 'retention',
        reason:   'Retention policy missing or invalid (fail-closed)',
      }
    }

    const now = isValidDate(requestedAt) ? requestedAt : new Date()
    if (retainUntil.getTime() <= now.getTime()) {
      return {
        passed:   false,
        failedAt: 'retention',
        reason:   `Document retention expired at ${retainUntil.toISOString()}`,
      }
    }

    return { passed: true }
  }
}
