import { AuditLockService } from './AuditLockService'
import { PolicyCheck, PolicyContext, PolicyCheckResult } from './types'
import { TenantBoundaryCheck } from './checks/TenantBoundaryCheck'
import { ScopeCheck } from './checks/ScopeCheck'
import { TopicPermissionCheck } from './checks/TopicPermissionCheck'
import { StatusCheck } from './checks/StatusCheck'
import { LegalHoldCheck } from './checks/LegalHoldCheck'
import { RetentionCheck } from './checks/RetentionCheck'
import { EffectiveDateCheck } from './checks/EffectiveDateCheck'

function isValidDate(d: unknown): d is Date {
  return d instanceof Date && !Number.isNaN(d.getTime())
}

// Deterministic governance evaluation. Gates run in the canonical order and the
// first failure short-circuits — the evaluation is fully replayable.
//
//   tenant_boundary → scope → topic_permission → status
//     → legal_hold → retention → effective_date
export class PolicyEngine {
  private gates: PolicyCheck[]

  constructor(private auditLock: AuditLockService) {
    this.gates = [
      new TenantBoundaryCheck(),
      new ScopeCheck(),
      new TopicPermissionCheck(),
      new StatusCheck(),
      new LegalHoldCheck(),
      new RetentionCheck(),
      new EffectiveDateCheck(),
    ]
  }

  async evaluate(ctx: PolicyContext): Promise<PolicyCheckResult> {
    // Fail-closed on malformed context.
    if (!ctx || !ctx.claim || !ctx.boundary || !ctx.resource) {
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
            ctx.resource.resourceId,
            ctx.resource.tenantId,
            result.reason ?? 'legal hold',
            // The resource's own policy version anchors the lock even when the
            // caller supplies no extra provenance.
            { policyVersion: ctx.resource.policyVersion, ...ctx.provenance },
          )
        }
        return result
      }
    }

    return { passed: true }
  }
}
