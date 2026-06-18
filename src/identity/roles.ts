// Canonical role hierarchy (matches the SQL `role` check constraint).
// Single source of truth for role ordering. Unknown roles resolve to level 0
// (denied) — fail-closed by construction.
//
// NOTE: in the canonical (topic-based) model a role does NOT by itself grant
// access to evidence. A role is the key used to look up its `allowed_topics` in
// the `policies` table. The level ordering below is only used for coarse
// privilege comparisons (e.g. "manager and above"), never for evidence
// authorisation — that is always topic + scope based.

export type Role = 'staff' | 'supervisor' | 'manager' | 'admin'

const ROLE_LEVELS: Record<Role, number> = {
  staff:      1,
  supervisor: 2,
  manager:    3,
  admin:      4,
}

export function isRole(v: unknown): v is Role {
  return typeof v === 'string' && Object.prototype.hasOwnProperty.call(ROLE_LEVELS, v)
}

export function roleLevel(role: string | undefined | null): number {
  if (!role) return 0
  return ROLE_LEVELS[role as Role] ?? 0
}

// True when `subjectRole` is at or above `minRole` in the hierarchy. Unknown
// subject roles always fail closed.
export function roleAtLeast(subjectRole: string, minRole: Role): boolean {
  const subject = roleLevel(subjectRole)
  if (subject === 0) return false
  return subject >= roleLevel(minRole)
}
