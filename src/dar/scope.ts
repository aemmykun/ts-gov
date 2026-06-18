import { AuthorityScope } from './types'

// Canonical scope-match rule shared by the corpus filter and the policy engine,
// so authorisation is identical everywhere (tenant → family → child).
//
//   - Tenant-global evidence (familyId === null) is visible to any subject that
//     has at least one authority scope in the tenant.
//   - A family-level grant (scope.childId === null) sees all children in that
//     family.
//   - Family-level evidence (childId === null) is visible to any member of the
//     family, including child-scoped members.
//   - Otherwise the child ids must match exactly.
export function scopeMatches(
  scopes: readonly AuthorityScope[],
  familyId: string | null,
  childId: string | null,
): boolean {
  if (familyId === null) return scopes.length > 0
  return scopes.some(s => {
    if (s.familyId !== familyId) return false
    if (s.childId === null) return true
    if (childId === null) return true
    return s.childId === childId
  })
}
