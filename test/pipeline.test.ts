import {
  TenantSagePipeline, PolicyDecisionProvider,
  NoAuthorityError, NoEvidenceError, PolicyDeniedError,
} from '../src/TenantSagePipeline'
import { TenantIsolationGuard } from '../src/identity/TenantIsolationGuard'
import { DAREngine } from '../src/dar/DAREngine'
import { InMemoryAssignmentResolver } from '../src/assignments/InMemoryAssignmentResolver'
import { InMemoryTopicPolicyProvider } from '../src/policy/TopicPolicyProvider'
import { TrustRAGRetriever } from '../src/trustrag/TrustRAGRetriever'
import { VectorIndex, VectorQuery } from '../src/trustrag/types'
import { GovernedChunk } from '../src/runtime/ApprovedEvidenceCorpus'
import { EvidenceLedger } from '../src/ledger/EvidenceLedger'
import { InMemoryLedgerStore } from '../src/ledger/LedgerStore'
import { UserAssignment } from '../src/assignments/types'
import { TenantClaim } from '../src/identity/types'
import { Role } from '../src/identity/roles'

const PAST   = new Date(Date.now() - 86_400_000)
const FUTURE = new Date(Date.now() + 86_400_000 * 365)

const claim: TenantClaim = {
  userId: 'user-001', tenantId: 'tenant-A', provider: 'entra', verifiedAt: Date.now(),
}

const corpus: GovernedChunk[] = [
  { chunkId: 'c1', sourceId: 's1', tenantId: 'tenant-A', familyId: 'family-X', childId: null,
    topicKey: 'maintenance', status: 'ACTIVE', legalHold: false, validFrom: PAST, validTo: FUTURE, content: 'allowed' },
  { chunkId: 'c2', sourceId: 's2', tenantId: 'tenant-B', familyId: 'family-X', childId: null,
    topicKey: 'maintenance', status: 'ACTIVE', legalHold: false, validFrom: PAST, validTo: FUTURE, content: 'cross-tenant' },
]

// The index honours the predicate (tenant + topic). The corpus then re-checks.
class PredicateIndex implements VectorIndex {
  async searchWithin(q: VectorQuery): Promise<GovernedChunk[]> {
    return corpus.filter(c =>
      c.tenantId === q.predicate.tenantId &&
      q.predicate.eligibleTopics.includes(c.topicKey),
    )
  }
}

function topics() {
  return new InMemoryTopicPolicyProvider().set({
    policyId: 'pol-1', tenantId: 'tenant-A', role: 'manager',
    allowedTopics: ['maintenance', 'billing'], version: '2026.06', active: true,
  })
}

function buildPipeline(resolver: InMemoryAssignmentResolver, policy?: PolicyDecisionProvider) {
  const store = new InMemoryLedgerStore()
  return {
    store,
    pipeline: new TenantSagePipeline(
      new TenantIsolationGuard(),
      new DAREngine(resolver, topics(), { policyVersion: 'fallback' }),
      new TrustRAGRetriever(new PredicateIndex()),
      new EvidenceLedger(store),
      async (_q, chunks) => ({ response: `answer over ${chunks.length} chunks`, modelUsed: 'test-model', tokenCount: 42 }),
      policy,
    ),
  }
}

const assignment = (overrides: Partial<UserAssignment> = {}): UserAssignment => ({
  assignmentId: 'asg-001', assignmentVersion: 'v1',
  userId: 'user-001', tenantId: 'tenant-A',
  familyId: 'family-X', childId: null, role: 'manager' as Role,
  startedAt: new Date().toISOString(), endedAt: null, source: 'test',
  ...overrides,
})

const managerResolver = () => new InMemoryAssignmentResolver().grant(assignment())

describe('Canonical runtime flow (Identity → DAR → TrustRAG → Corpus → Generation → Ledger)', () => {
  test('authorised manager retrieves only in-boundary evidence and a ledger block is written', async () => {
    const { pipeline, store } = buildPipeline(managerResolver())

    const result = await pipeline.run({
      claim, requestedTenantId: 'tenant-A', query: 'q', embedding: [0.1, 0.2], topK: 5, ruleVersion: '4.1',
    })

    expect(result.chunks.map(c => c.chunkId)).toEqual(['c1'])
    expect(result.response).toBe('answer over 1 chunks')

    expect(result.block.blockNumber).toBe(1)
    expect(result.block.decision).toBe('ALLOW')
    expect(result.block.retrievedEvidenceIds).toEqual(['c1'])
    const verify = await new EvidenceLedger(store).verifyChain('tenant-A', 1, 1)
    expect(verify.valid).toBe(true)
  })

  test('ledger block carries replay provenance (snapshot + policy version + boundary hash)', async () => {
    const { pipeline } = buildPipeline(managerResolver())
    const result = await pipeline.run({
      claim, requestedTenantId: 'tenant-A', query: 'q', embedding: [0.1], topK: 5, ruleVersion: '4.1',
    })
    expect(result.block.authority).not.toBeNull()
    expect(result.block.authority?.authoritySnapshotId).toHaveLength(64)
    expect(result.block.authority?.policyVersion).toBe('2026.06')
    expect(result.block.authority?.boundaryHash).toHaveLength(64)
    expect(result.block.darDecisionHash).toBe(result.block.authority?.boundaryHash)
  })

  test('NO_AUTHORITY: no assignment is refused before the index is queried (no block)', async () => {
    const { pipeline, store } = buildPipeline(new InMemoryAssignmentResolver())

    await expect(
      pipeline.run({ claim, requestedTenantId: 'tenant-A', query: 'q', embedding: [0.1], topK: 5, ruleVersion: '4.1' }),
    ).rejects.toThrow(NoAuthorityError)

    expect(await store.getLatest('tenant-A')).toBeNull()
  })

  test('TENANT_ISOLATION: a mismatched requestedTenantId is rejected', async () => {
    const { pipeline } = buildPipeline(managerResolver())
    await expect(
      pipeline.run({ claim, requestedTenantId: 'tenant-B', query: 'q', embedding: [0.1], topK: 5, ruleVersion: '4.1' }),
    ).rejects.toThrow('TENANT_ISOLATION')
  })

  test('NO_EVIDENCE: out-of-scope assignment ghosts all chunks before generation', async () => {
    const resolver = new InMemoryAssignmentResolver().grant(assignment({ familyId: 'family-Z' }))
    const { pipeline, store } = buildPipeline(resolver)
    await expect(
      pipeline.run({ claim, requestedTenantId: 'tenant-A', query: 'q', embedding: [0.1], topK: 5, ruleVersion: '4.1' }),
    ).rejects.toThrow(NoEvidenceError)
    expect(await store.getLatest('tenant-A')).toBeNull()
  })

  test('POLICY_DENIED: an injected policy gate failure blocks generation', async () => {
    const denyingPolicy: PolicyDecisionProvider = {
      async evaluate() { return { passed: false, reason: 'legal hold active' } },
    }
    const { pipeline, store } = buildPipeline(managerResolver(), denyingPolicy)
    await expect(
      pipeline.run({ claim, requestedTenantId: 'tenant-A', query: 'q', embedding: [0.1], topK: 5, ruleVersion: '4.1' }),
    ).rejects.toThrow(PolicyDeniedError)
    expect(await store.getLatest('tenant-A')).toBeNull()
  })
})
