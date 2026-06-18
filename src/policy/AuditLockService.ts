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

// Sink for legal-hold audit locks. Implemented by the in-memory reference
// service and by the Postgres-backed service (which persists to `audit_locks`).
export interface AuditLockSink {
  lock(
    documentId: string,
    tenantId: string,
    reason: string,
    provenance?: AuditLockProvenance,
  ): AuditLockRecord | Promise<AuditLockRecord>
}

export class AuditLockService implements AuditLockSink {
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
