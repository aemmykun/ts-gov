// Records audit locks raised when a legal-hold violation is encountered.
// In production this would persist to the immutable ledger / compliance store.

export interface AuditLockRecord {
  documentId: string
  tenantId:   string
  reason:     string
  lockedAt:   string
}

export class AuditLockService {
  private locks: AuditLockRecord[] = []

  lock(documentId: string, tenantId: string, reason: string): AuditLockRecord {
    const record: AuditLockRecord = {
      documentId,
      tenantId,
      reason,
      lockedAt: new Date().toISOString(),
    }
    this.locks.push(record)
    return record
  }

  list(): readonly AuditLockRecord[] {
    return this.locks
  }
}
