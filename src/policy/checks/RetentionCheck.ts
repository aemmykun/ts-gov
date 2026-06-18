import { PolicyCheck, PolicyContext, PolicyCheckResult } from '../types'

function isValidDate(d: unknown): d is Date {
  return d instanceof Date && !Number.isNaN(d.getTime())
}

// Retention: a resource is unretrievable once its validTo has passed. A null
// validTo means "retain indefinitely". An invalid (non-null) validTo fails closed.
export class RetentionCheck implements PolicyCheck {
  run(ctx: PolicyContext): PolicyCheckResult {
    const { resource, requestedAt } = ctx
    const validTo = resource.validTo ?? null

    if (validTo === null) return { passed: true }

    if (!isValidDate(validTo)) {
      return {
        passed:   false,
        failedAt: 'retention',
        reason:   'Retention validTo is invalid (fail-closed)',
      }
    }

    const now = isValidDate(requestedAt) ? requestedAt : new Date()
    if (validTo.getTime() <= now.getTime()) {
      return {
        passed:   false,
        failedAt: 'retention',
        reason:   `Resource retention expired at ${validTo.toISOString()}`,
      }
    }

    return { passed: true }
  }
}
