// Records audit locks raised when a legal-hold violation is encountered.
// In production this would persist to the immutable ledger / compliance store.

// Authority provenance attached to a governance event so an auditor can answer
// "why was this lock raised?" — which authority snapshot / policy / boundary /
// rule set produced the decision — not merely "was a lock raised?".
export interface AuditLockProvenance {
  authoritySnapshotId?: string
  policyVersion?:       string
  boundaryHash?:        string
  ruleVersion?:         string
}

export interface AuditLockRecord extends AuditLockProvenance {
  documentId: string
  tenantId:   string
  reason:     string
  lockedAt:   string
}

export class AuditLockService {
  private locks: AuditLockRecord[] = []

  lock(
    documentId: string,
    tenantId: string,
    reason: string,
    provenance: AuditLockProvenance = {},
  ): AuditLockRecord {
    const record: AuditLockRecord = {
      documentId,
      tenantId,
      reason,
      lockedAt: new Date().toISOString(),
      ...provenance,
    }
    this.locks.push(record)
    return record
  }

  list(): readonly AuditLockRecord[] {
    return this.locks
  }
}
