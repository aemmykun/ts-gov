// Serialises ledger commits per tenant so two concurrent commits can never read
// the same prevBlock and fork the chain. The default implementation is
// in-process; a distributed deployment injects a Postgres advisory-lock backed
// implementation so the guarantee holds across processes/instances.
export interface LedgerLock {
  withLock<T>(tenantId: string, fn: () => Promise<T>): Promise<T>
}

// In-process per-tenant mutex: commits for a tenant run in submission order by
// chaining onto the previous in-flight promise. Single-process only.
export class InProcessLedgerLock implements LedgerLock {
  private locks: Map<string, Promise<unknown>> = new Map()

  async withLock<T>(tenantId: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.locks.get(tenantId) ?? Promise.resolve()
    const next = prev.catch(() => undefined).then(fn)
    // Track completion (swallowing errors) so the chain continues after a failure.
    this.locks.set(tenantId, next.catch(() => undefined))
    return next
  }
}
