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

// Lowest privilege level among a set of roles. This is the MINIMUM THRESHOLD a
// subject must reach. Empty / all-unknown sets return Infinity so callers fail
// closed.
export function requiredLevel(thresholdRoles: readonly string[]): number {
  const levels = thresholdRoles.map(roleLevel).filter(l => l > 0)
  if (levels.length === 0) return Infinity
  return Math.min(...levels)
}

// IMPORTANT — `thresholdRoles` is a MINIMUM-THRESHOLD set, NOT an OR allow-list.
//
// The requirement is the LOWEST-privilege role in the list; any subject at or
// above that level satisfies it. So:
//
//   ['owner','admin','manager']  ⇒  "manager and above"   (min level = manager)
//   ['viewer','admin']           ⇒  "viewer and above"    (min level = viewer)  ← effectively everyone
//
// It does NOT mean "viewer OR admin". If you need an exact-match allow-list,
// do not use this function. Owner is an explicit superuser short-circuit.
export function roleMeetsThreshold(subjectRole: string, thresholdRoles: readonly string[]): boolean {
  if (subjectRole === 'owner') return true
  const subject = roleLevel(subjectRole)
  if (subject === 0) return false
  return subject >= requiredLevel(thresholdRoles)
}
