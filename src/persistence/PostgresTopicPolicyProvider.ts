import { Role } from '../identity/roles'
import { TopicPolicy, TopicPolicyProvider } from '../policy/TopicPolicyProvider'
import { PgContext } from './pg'

interface PolicyRow {
  id: string
  tenant_id: string
  role: string
  allowed_topics: string[]
  version: string
  active: boolean
}

// Topic-access policy provider backed by the `policies` table. A (tenant, role)
// with no active policy returns null, which grants NO topics (fail-closed).
export class PostgresTopicPolicyProvider implements TopicPolicyProvider {
  constructor(private pg: PgContext) {}

  async getPolicy(tenantId: string, role: Role): Promise<TopicPolicy | null> {
    const row = await this.pg.withTenant({ tenantId }, async client => {
      const res = await client.query<PolicyRow>(
        `SELECT id, tenant_id, role, allowed_topics, version, active
           FROM policies
          WHERE tenant_id = $1 AND role = $2 AND active = true
          ORDER BY created_at DESC
          LIMIT 1`,
        [tenantId, role],
      )
      return res.rows[0] ?? null
    })
    if (!row) return null
    return {
      policyId: row.id,
      tenantId: row.tenant_id,
      role: row.role as Role,
      allowedTopics: row.allowed_topics,
      version: row.version,
      active: row.active,
    }
  }
}
