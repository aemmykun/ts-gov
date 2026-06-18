import { AuditLockService } from './AuditLockService'
import { PolicyCheck, PolicyContext, PolicyCheckResult } from './types'
import { RetentionCheck } from './checks/RetentionCheck'
import { LegalHoldCheck } from './checks/LegalHoldCheck'
import { RolePermissionCheck } from './checks/RolePermissionCheck'
import { EffectiveDateCheck } from './checks/EffectiveDateCheck'

function isValidDate(d: unknown): d is Date {
  return d instanceof Date && !Number.isNaN(d.getTime())
}

// Deterministic 4-gate policy evaluation. Gates run in a fixed order and the
// first failure short-circuits — the evaluation is fully replayable.
export class PolicyEngine {
  private gates: PolicyCheck[]

  constructor(private auditLock: AuditLockService) {
    this.gates = [
      new RetentionCheck(),      // gate 1
      new LegalHoldCheck(),      // gate 2
      new RolePermissionCheck(), // gate 3
      new EffectiveDateCheck(),  // gate 4
    ]
  }

  async evaluate(ctx: PolicyContext): Promise<PolicyCheckResult> {
    // Fail-closed on malformed context.
    if (!ctx || !ctx.claim || !ctx.document) {
      return { passed: false, reason: 'Invalid policy context (fail-closed)' }
    }
    if (!isValidDate(ctx.requestedAt)) {
      return { passed: false, reason: 'Invalid requestedAt timestamp (fail-closed)' }
    }

    for (const gate of this.gates) {
      const result = gate.run(ctx)
      if (!result.passed) {
        if (result.failedAt === 'legal_hold' && result.auditLocked) {
          this.auditLock.lock(
            ctx.document.documentId,
            ctx.document.tenantId,
            result.reason ?? 'legal hold',
            // The document's own policy version anchors the lock even when the
            // caller supplies no extra provenance.
            { policyVersion: ctx.document.policyVersion, ...ctx.provenance },
          )
        }
        return result
      }
    }

    return { passed: true }
  }
}
