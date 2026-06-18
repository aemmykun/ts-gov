import { Pool, PoolClient, PoolConfig } from 'pg'

// Per-request governance context. tenantId is mandatory (RLS fails closed
// without it); familyId/childId narrow the tenant→family→child boundary chain
// and map to the app.family_id / app.child_id session GUCs the schema's RLS
// policies read.
export interface TenantContext {
  tenantId: string
  familyId?: string | null
  childId?: string | null
}

export interface PgContextOptions {
  pool: Pool
  // Optional non-superuser role to assume per transaction. Postgres superusers
  // BYPASS row-level security, so production/integration use should set this to
  // the least-privileged application role so RLS is actually enforced.
  appRole?: string
}

const IDENT = /^[a-zA-Z_][a-zA-Z0-9_]*$/

// Thin wrapper around a pg Pool that runs every unit of work inside a
// transaction with the governance GUCs set LOCAL (so they reset automatically
// at COMMIT/ROLLBACK and never leak across pooled connections). This is the
// single place tenant context is bound to the database session.
export class PgContext {
  private pool: Pool
  private appRole?: string

  constructor(opts: PgContextOptions) {
    this.pool = opts.pool
    if (opts.appRole && !IDENT.test(opts.appRole)) {
      throw new Error(`PG: invalid appRole identifier '${opts.appRole}'`)
    }
    this.appRole = opts.appRole
  }

  static fromConfig(config: PoolConfig, appRole?: string): PgContext {
    return new PgContext({ pool: new Pool(config), appRole })
  }

  get rawPool(): Pool {
    return this.pool
  }

  // Run `fn` inside a tenant-scoped transaction. The governance GUCs are set
  // LOCAL and the optional app role is assumed for the duration, so RLS is
  // enforced exactly as it would be for a real request.
  async withTenant<T>(
    ctx: TenantContext,
    fn: (client: PoolClient) => Promise<T>,
  ): Promise<T> {
    const client = await this.pool.connect()
    try {
      await client.query('BEGIN')
      if (this.appRole) {
        await client.query(`SET LOCAL ROLE "${this.appRole}"`)
      }
      // tenant_id is always set. family_id/child_id are left UNSET when absent
      // (rather than set to ''), so the RLS predicates read them as NULL — an
      // empty string would fail the ::uuid cast. SET LOCAL is transaction-scoped
      // so these never leak across pooled connections.
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [ctx.tenantId])
      if (ctx.familyId != null) {
        await client.query("SELECT set_config('app.family_id', $1, true)", [ctx.familyId])
      }
      if (ctx.childId != null) {
        await client.query("SELECT set_config('app.child_id', $1, true)", [ctx.childId])
      }
      const result = await fn(client)
      await client.query('COMMIT')
      return result
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined)
      throw err
    } finally {
      client.release()
    }
  }

  async end(): Promise<void> {
    await this.pool.end()
  }
}

// Format a numeric embedding as a pgvector literal (e.g. [0.1,0.2,0.3]).
export function toVectorLiteral(embedding: number[]): string {
  return `[${embedding.join(',')}]`
}
