import { AssignmentResolver, UserAssignment } from './types'

// Reference resolver backed by an in-memory authoritative store. In production
// this is the user-assignment service (HRIS/SCIM-fed). An empty store denies
// everyone — there is no implicit authority.
export class InMemoryAssignmentResolver implements AssignmentResolver {
  private store: Map<string, UserAssignment> = new Map()

  private key(userId: string, tenantId: string): string {
    return `${tenantId}::${userId}`
  }

  grant(assignment: UserAssignment): this {
    this.store.set(this.key(assignment.userId, assignment.tenantId), assignment)
    return this
  }

  revoke(userId: string, tenantId: string): this {
    this.store.delete(this.key(userId, tenantId))
    return this
  }

  async resolve(userId: string, tenantId: string): Promise<UserAssignment | null> {
    return this.store.get(this.key(userId, tenantId)) ?? null
  }
}
