import { AssignmentResolver, UserAssignment } from '../assignments/types'
import { Role } from '../identity/roles'
import { PgContext } from './pg'

interface AssignmentRow {
  id: string
  assignment_version: string
  user_id: string
  tenant_id: string
  family_id: string
  child_id: string | null
  role: string
  started_at: Date
  ended_at: Date | null
  source: string
}

// Authoritative assignment resolver backed by the `user_assignments` table.
// Only ACTIVE assignments (ended_at IS NULL) are returned — an identity with no
// active row gets an empty array, so callers fail closed (no assignment ⇒ no
// authority). The user_assignments table has no assignment_version/source
// columns in the base schema; they are carried in a metadata-free form here by
// deriving version from the row id (stable per row) and a constant source. If a
// deployment needs richer provenance, add those columns and select them.
export class PostgresAssignmentResolver implements AssignmentResolver {
  constructor(private pg: PgContext) {}

  async resolve(userId: string, tenantId: string): Promise<UserAssignment[]> {
    const rows = await this.pg.withTenant({ tenantId }, async client => {
      const res = await client.query<AssignmentRow>(
        `SELECT id,
                id::text AS assignment_version,
                user_id, tenant_id, family_id, child_id, role,
                started_at, ended_at,
                'user_assignments' AS source
           FROM user_assignments
          WHERE user_id = $1
            AND tenant_id = $2
            AND ended_at IS NULL
          ORDER BY started_at`,
        [userId, tenantId],
      )
      return res.rows
    })

    return rows.map(r => ({
      assignmentId: r.id,
      assignmentVersion: r.assignment_version,
      userId: r.user_id,
      tenantId: r.tenant_id,
      familyId: r.family_id,
      childId: r.child_id,
      role: r.role as Role,
      startedAt: r.started_at.toISOString(),
      endedAt: r.ended_at ? r.ended_at.toISOString() : null,
      source: r.source,
    }))
  }
}
