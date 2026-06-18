import { Pool } from 'pg'
import { LedgerLock } from '../ledger/LedgerLock'

// Distributed-safe ledger commit lock backed by Postgres session-level advisory
// locks. Commits for a given tenant are serialised across every process/instance
// connected to the same database (unlike the in-process default). The advisory
// key is derived from the tenant id via hashtext(), and the lock is always
// released on the same dedicated connection that acquired it.
export class PostgresLedgerLock implements LedgerLock {
  constructor(private pool: Pool) {}

  async withLock<T>(tenantId: string, fn: () => Promise<T>): Promise<T> {
    const client = await this.pool.connect()
    try {
      await client.query('SELECT pg_advisory_lock(hashtext($1)::bigint)', [tenantId])
      try {
        return await fn()
      } finally {
        await client
          .query('SELECT pg_advisory_unlock(hashtext($1)::bigint)', [tenantId])
          .catch(() => undefined)
      }
    } finally {
      client.release()
    }
  }
}
