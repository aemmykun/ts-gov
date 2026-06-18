// Canonical role hierarchy. Single source of truth for every authority decision.
// Unknown roles resolve to level 0 (denied) — fail-closed by construction.

export type Role = 'owner' | 'admin' | 'manager' | 'member' | 'viewer'

const ROLE_LEVELS: Record<Role, number> = {
  viewer:  1,
  member:  2,
  manager: 3,
  admin:   4,
  owner:   5,
}

export function roleLevel(role: string | undefined | null): number {
  if (!role) return 0
  return ROLE_LEVELS[role as Role] ?? 0
}

// Lowest privilege level that satisfies a set of allowed roles.
// Empty / all-unknown sets return Infinity so callers fail closed.
export function requiredLevel(allowedRoles: readonly string[]): number {
  const levels = allowedRoles.map(roleLevel).filter(l => l > 0)
  if (levels.length === 0) return Infinity
  return Math.min(...levels)
}

// A subject role satisfies the requirement when its level meets the lowest
// allowed level. Owner is an explicit superuser short-circuit.
export function roleSatisfies(subjectRole: string, allowedRoles: readonly string[]): boolean {
  if (subjectRole === 'owner') return true
  const subject = roleLevel(subjectRole)
  if (subject === 0) return false
  return subject >= requiredLevel(allowedRoles)
}
