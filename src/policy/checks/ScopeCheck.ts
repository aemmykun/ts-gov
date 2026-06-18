import { PolicyCheck, PolicyContext, PolicyCheckResult } from '../types'
import { scopeMatches } from '../../dar/scope'

// Family/child scope enforcement against the authoritative boundary scopes.
export class ScopeCheck implements PolicyCheck {
  run(ctx: PolicyContext): PolicyCheckResult {
    const { resource, boundary } = ctx
    if (!scopeMatches(boundary.scopes, resource.familyId, resource.childId)) {
      return {
        passed:   false,
        failedAt: 'scope',
        reason:   `Resource scope (family=${resource.familyId ?? 'null'}, child=${resource.childId ?? 'null'}) is outside the subject's authority`,
      }
    }
    return { passed: true }
  }
}
