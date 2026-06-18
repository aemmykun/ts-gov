import {
  TenantSagePipeline, PolicyDecisionProvider,
  NoAuthorityError, NoEvidenceError, PolicyDeniedError,
} from '../src/TenantSagePipeline'
import { TenantIsolationGuard } from '../src/identity/TenantIsolationGuard'
import { DAREngine } from '../src/dar/DAREngine'
import { InMemoryAssignmentResolver } from '../src/assignments/InMemoryAssignmentResolver'
import { TrustRAGRetriever } from '../src/trustrag/TrustRAGRetriever'
import { VectorIndex, VectorQuery } from '../src/trustrag/types'
import { GovernedChunk } from '../src/runtime/ApprovedEvidenceCorpus'
import { EvidenceLedger } from '../src/ledger/EvidenceLedger'
import { InMemoryLedgerStore } from '../src/ledger/LedgerStore'
import { TenantClaim } from '../src/identity/types'

const claim: TenantClaim = {
  userId: 'user-001', tenantId: 'tenant-A', provider: 'entra', verifiedAt: Date.now(),
}

const corpus: GovernedChunk[] = [
  { chunkId: 'c1', sourceId: 's1', tenantId: 'tenant-A', organisationId: 'org-1', familyId: 'family-X', content: 'allowed',
    governance: { status: 'active', allowedRoles: ['manager'], visibility: 'tenant' } },
  { chunkId: 'c2', sourceId: 's2', tenantId: 'tenant-B', organisationId: 'org-1', familyId: 'family-X', content: 'cross-tenant',
    governance: { status: 'active', allowedRoles: ['manager'], visibility: 'tenant' } },
]

class PredicateIndex implements VectorIndex {
  async searchWithin(q: VectorQuery): Promise<GovernedChunk[]> {
    return corpus.filter(c => q.predicate.tenantIds.includes(c.tenantId))
  }
}

function buildPipeline(resolver: InMemoryAssignmentResolver, policy?: PolicyDecisionProvider) {
  const store = new InMemoryLedgerStore()
  return {
    store,
    pipeline: new TenantSagePipeline(
      new TenantIsolationGuard(),
      new DAREngine(resolver, { policyVersion: '4.2.0' }),
      new TrustRAGRetriever(new PredicateIndex()),
      new EvidenceLedger(store),
      async (_q, chunks) => ({ response: `answer over ${chunks.length} chunks`, modelUsed: 'test-model', tokenCount: 42 }),
      policy,
    ),
  }
}

const managerResolver = () => new InMemoryAssignmentResolver().grant({
  assignmentId: 'asg-001', assignmentVersion: 'v1',
  userId: 'user-001', tenantId: 'tenant-A',
  organisationIds: ['org-1'], scopeIds: [], familyIds: ['family-X'],
  role: 'manager', classificationClearance: 'restricted', sensitivityClearance: 'critical',
  source: 'test', assignedAt: new Date().toISOString(),
})

describe('Canonical runtime flow (Identity → DAR → TrustRAG → Corpus → Generation → Ledger)', () => {
  test('authorised manager retrieves only in-boundary evidence and a ledger block is written', async () => {
    const { pipeline, store } = buildPipeline(managerResolver())

    const result = await pipeline.run({
      claim, requestedTenantId: 'tenant-A', query: 'q', embedding: [0.1, 0.2], topK: 5, ruleVersion: '4.1',
    })

    // Cross-tenant chunk c2 is ghosted out.
    expect(result.chunks.map(c => c.chunkId)).toEqual(['c1'])
    expect(result.response).toBe('answer over 1 chunks')

    // Ledger recorded the run and the chain verifies.
    expect(result.block.blockNumber).toBe(1)
    const verify = await new EvidenceLedger(store).verifyChain('tenant-A', 1, 1)
    expect(verify.valid).toBe(true)
  })

  test('ledger block carries replay provenance (snapshot + policy version + boundary hash)', async () => {
    const { pipeline } = buildPipeline(managerResolver())
    const result = await pipeline.run({
      claim, requestedTenantId: 'tenant-A', query: 'q', embedding: [0.1], topK: 5, ruleVersion: '4.1',
    })
    expect(result.block.authority).not.toBeNull()
    expect(result.block.authority?.authoritySnapshotId).toBe('asg-001@v1')
    expect(result.block.authority?.policyVersion).toBe('4.2.0')
    expect(result.block.authority?.boundaryHash).toHaveLength(64)
  })

  test('NO_AUTHORITY: no assignment is refused before the index is queried (no block)', async () => {
    const { pipeline, store } = buildPipeline(new InMemoryAssignmentResolver())

    await expect(
      pipeline.run({ claim, requestedTenantId: 'tenant-A', query: 'q', embedding: [0.1], topK: 5, ruleVersion: '4.1' }),
    ).rejects.toThrow(NoAuthorityError)

    const latest = await store.getLatest('tenant-A')
    expect(latest).toBeNull() // nothing generated, nothing logged
  })

  test('TENANT_ISOLATION: a mismatched requestedTenantId is rejected', async () => {
    const { pipeline } = buildPipeline(managerResolver())
    await expect(
      pipeline.run({ claim, requestedTenantId: 'tenant-B', query: 'q', embedding: [0.1], topK: 5, ruleVersion: '4.1' }),
    ).rejects.toThrow('TENANT_ISOLATION')
  })

  test('NO_EVIDENCE: empty approved corpus is refused before generation', async () => {
    // family-Z assignment ⇒ all tenant-A chunks are ghosted ⇒ no evidence.
    const resolver = new InMemoryAssignmentResolver().grant({
      assignmentId: 'asg-001', assignmentVersion: 'v1',
      userId: 'user-001', tenantId: 'tenant-A',
      organisationIds: ['org-1'], scopeIds: [], familyIds: ['family-Z'],
      role: 'manager', classificationClearance: 'restricted', sensitivityClearance: 'critical',
      source: 'test', assignedAt: new Date().toISOString(),
    })
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
