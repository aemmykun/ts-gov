import { Role } from '../identity/roles'

// Authoritative topic-access policy (mirrors the SQL `policies` table).
// A policy maps a (tenant, role) to the set of topic keys that role is allowed
// to retrieve. This is the canonical authorisation primitive: evidence is
// reachable only if its `topic_key` is in the caller's eligible topics.
export interface TopicPolicy {
  policyId:      string
  tenantId:      string
  role:          Role
  allowedTopics: string[]
  version:       string
  active:        boolean
}

export interface TopicPolicyProvider {
  // Active policy for a (tenant, role), or null when none is defined. A missing
  // policy grants NO topics (fail-closed).
  getPolicy(tenantId: string, role: Role): Promise<TopicPolicy | null>
}

// Reference in-memory provider. An empty store grants no topics to anyone.
export class InMemoryTopicPolicyProvider implements TopicPolicyProvider {
  private store: TopicPolicy[] = []

  set(policy: TopicPolicy): this {
    this.store.push(policy)
    return this
  }

  async getPolicy(tenantId: string, role: Role): Promise<TopicPolicy | null> {
    return (
      this.store.find(p => p.tenantId === tenantId && p.role === role && p.active) ?? null
    )
  }
}
