import { PolicyCheck, PolicyContext, PolicyCheckResult } from '../types'

// Topic-based authorisation (canonical primitive): a resource is reachable only
// when its topic_key is in the subject's eligible topics (the union of
// allowed_topics for the role(s) they hold). An empty eligible-topics set denies
// everything (fail-closed).
export class TopicPermissionCheck implements PolicyCheck {
  run(ctx: PolicyContext): PolicyCheckResult {
    const { resource, boundary } = ctx
    if (!boundary.eligibleTopics.includes(resource.topicKey)) {
      return {
        passed:   false,
        failedAt: 'topic_permission',
        reason:   `Topic '${resource.topicKey}' is not in the subject's eligible topics`,
      }
    }
    return { passed: true }
  }
}
