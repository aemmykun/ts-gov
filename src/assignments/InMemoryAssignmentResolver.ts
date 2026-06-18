import { AssignmentResolver, UserAssignment } from './types'

// Reference resolver backed by an in-memory authoritative store. In production
// this is the user-assignment service (HRIS/SCIM-fed) backed by the
// `user_assignments` table. An empty store denies everyone — there is no
// implicit authority. Only ACTIVE assignments (endedAt === null) are returned.
export class InMemoryAssignmentResolver implements AssignmentResolver {
  private store: UserAssignment[] = []

  grant(assignment: UserAssignment): this {
    this.store.push(assignment)
    return this
  }

  // End every active assignment for a user in a tenant (sets endedAt).
  revoke(userId: string, tenantId: string, at: string = new Date().toISOString()): this {
    for (const a of this.store) {
      if (a.userId === userId && a.tenantId === tenantId && a.endedAt === null) {
        a.endedAt = at
      }
    }
    return this
  }

  async resolve(userId: string, tenantId: string): Promise<UserAssignment[]> {
    return this.store.filter(
      a => a.userId === userId && a.tenantId === tenantId && a.endedAt === null,
    )
  }
}
