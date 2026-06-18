import { PolicyCheck, PolicyContext, PolicyCheckResult } from '../types'

export class LegalHoldCheck implements PolicyCheck {
  run(ctx: PolicyContext): PolicyCheckResult {
    const { resource } = ctx

    // Strict boolean identity: a truthy string like 'true' is NOT a hold.
    if (resource.legalHold === true) {
      const reason = resource.legalHoldReason
        ? `Resource under legal hold: ${resource.legalHoldReason}`
        : 'Resource under legal hold (no reason recorded — flag for compliance review)'

      return {
        passed:      false,
        failedAt:    'legal_hold',
        reason,
        auditLocked: true,
      }
    }

    return { passed: true }
  }
}
