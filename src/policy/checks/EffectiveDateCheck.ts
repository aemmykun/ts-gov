import { PolicyCheck, PolicyContext, PolicyCheckResult } from '../types'

function isValidDate(d: unknown): d is Date {
  return d instanceof Date && !Number.isNaN(d.getTime())
}

export class EffectiveDateCheck implements PolicyCheck {
  run(ctx: PolicyContext): PolicyCheckResult {
    const { document, requestedAt } = ctx

    // Lifecycle status is evaluated BEFORE the date window: a quarantined doc
    // with a valid date range must still be rejected.
    if (document.status !== 'active') {
      return {
        passed:   false,
        failedAt: 'effective_date',
        reason:   `Document status '${document.status}' (e.g. quarantined) is not retrievable`,
      }
    }

    const { effectiveFrom, effectiveTo } = document

    if (!isValidDate(effectiveFrom) || !isValidDate(effectiveTo)) {
      return {
        passed:   false,
        failedAt: 'effective_date',
        reason:   'Effective date window is invalid (fail-closed)',
      }
    }

    if (effectiveFrom.getTime() > effectiveTo.getTime()) {
      return {
        passed:   false,
        failedAt: 'effective_date',
        reason:   'effectiveFrom is after effectiveTo — data integrity error',
      }
    }

    const now = isValidDate(requestedAt) ? requestedAt : new Date()
    if (now.getTime() < effectiveFrom.getTime()) {
      return {
        passed:   false,
        failedAt: 'effective_date',
        reason:   'Document is not yet effective',
      }
    }
    if (now.getTime() > effectiveTo.getTime()) {
      return {
        passed:   false,
        failedAt: 'effective_date',
        reason:   'Document is past its effective window',
      }
    }

    return { passed: true }
  }
}
