import { TenantSagePipeline } from '../src/TenantSagePipeline'
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
  userId: 'user-001', tenantId: 'tenant-A', familyId: 'family-X',
  role: 'manager', orgUnit: 'eng', provider: 'entra', verifiedAt: Date.now(),
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

function buildPipeline(resolver: InMemoryAssignmentResolver) {
  const store = new InMemoryLedgerStore()
  return {
    store,
    pipeline: new TenantSagePipeline(
      new TenantIsolationGuard(),
      new DAREngine(resolver),
      new TrustRAGRetriever(new PredicateIndex()),
      new EvidenceLedger(store),
      async (_q, chunks) => ({ response: `answer over ${chunks.length} chunks`, modelUsed: 'test-model', tokenCount: 42 }),
    ),
  }
}

describe('Canonical runtime flow (Identity → DAR → TrustRAG → Corpus → Generation → Ledger)', () => {
  test('authorised manager retrieves only in-boundary evidence and a ledger block is written', async () => {
    const resolver = new InMemoryAssignmentResolver().grant({
      assignmentId: 'asg-001', assignmentVersion: 'v1',
      userId: 'user-001', tenantId: 'tenant-A',
      organisationIds: ['org-1'], scopeIds: [], familyIds: ['family-X'],
      role: 'manager', classificationClearance: 'restricted', sensitivityClearance: 'critical',
      source: 'test', assignedAt: new Date().toISOString(),
    })
    const { pipeline, store } = buildPipeline(resolver)

    const result = await pipeline.run({
      claim, query: 'q', embedding: [0.1, 0.2], topK: 5, ruleVersion: '4.1',
    })

    // Cross-tenant chunk c2 is ghosted out.
    expect(result.chunks.map(c => c.chunkId)).toEqual(['c1'])
    expect(result.response).toBe('answer over 1 chunks')

    // Ledger recorded the run and the chain verifies.
    expect(result.block.blockNumber).toBe(1)
    const verify = await new EvidenceLedger(store).verifyChain('tenant-A', 1, 1)
    expect(verify.valid).toBe(true)
  })

  test('user without an authoritative assignment is refused (fail-closed, no block)', async () => {
    const { pipeline, store } = buildPipeline(new InMemoryAssignmentResolver())

    await expect(
      pipeline.run({ claim, query: 'q', embedding: [0.1], topK: 5, ruleVersion: '4.1' }),
    ).rejects.toThrow('retrieval refused')

    const latest = await store.getLatest('tenant-A')
    expect(latest).toBeNull() // nothing generated, nothing logged
  })
})
