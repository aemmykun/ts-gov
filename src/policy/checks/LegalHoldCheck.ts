import { PolicyCheck, PolicyContext, PolicyCheckResult } from '../types'

export class LegalHoldCheck implements PolicyCheck {
  run(ctx: PolicyContext): PolicyCheckResult {
    const { document } = ctx

    // Strict boolean identity: a truthy string like 'true' is NOT a hold.
    if (document.legalHold === true) {
      const reason = document.legalHoldReason
        ? `Document under legal hold: ${document.legalHoldReason}`
        : 'Document under legal hold (no reason recorded — flag for compliance review)'

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
