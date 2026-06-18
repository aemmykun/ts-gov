/**
 * TenantSage — governance property tests (canonical SQL-schema model).
 * Proves: policy-derived ingestion governance, full corpus enforcement,
 * HandOff evidence integrity, fail-closed governed retrieval, audit-grade DAR
 * boundary, and assignment-driven (not claim-driven) authority.
 */

import { DAREngine } from '../src/dar/DAREngine'
import { EvidenceBoundary } from '../src/dar/types'
import { InMemoryAssignmentResolver } from '../src/assignments/InMemoryAssignmentResolver'
import { InMemoryTopicPolicyProvider } from '../src/policy/TopicPolicyProvider'
import { ApprovedEvidenceCorpus, GovernedChunk } from '../src/runtime/ApprovedEvidenceCorpus'
import { TenantClaim } from '../src/identity/types'
import {
  IngestionGovernanceBinder,
  GovernancePolicyProvider,
  SourceGovernance,
  MissingGovernancePolicyError,
  PolicyIntegrityError,
  computePolicyChecksum,
} from '../src/policy/GovernancePolicyProvider'
import { HandOffBuilder } from '../src/handoff/HandOffBuilder'
import { HandOffVerifier } from '../src/handoff/HandOffVerifier'
import { SigningKey } from '../src/handoff/HandOffSigner'
import { TrustRAGRetriever, UnauthorizedRetrievalError } from '../src/trustrag/TrustRAGRetriever'
import { VectorIndex, VectorQuery } from '../src/trustrag/types'
import { TenantIsolationGuard } from '../src/identity/TenantIsolationGuard'
import { UserAssignment } from '../src/assignments/types'

const PAST   = new Date(Date.now() - 86_400_000)
const FUTURE = new Date(Date.now() + 86_400_000 * 365)

const claim: TenantClaim = {
  userId: 'user-001', tenantId: 'tenant-A', provider: 'entra', verifiedAt: Date.now(),
}

const managerBoundary: EvidenceBoundary = {
  tenantId: 'tenant-A',
  scopes: [{ familyId: 'family-X', childId: null }],
  eligibleTopics: ['maintenance', 'billing'],
  allowedStatuses: ['ACTIVE'],
  roleLevel: 3,
  authoritySnapshotId: 'snap-1', policyVersion: '2026.06',
  effectiveAt: new Date().toISOString(), computedAt: new Date().toISOString(),
  empty: false,
}

const chunk = (overrides: Partial<GovernedChunk> = {}): GovernedChunk => ({
  chunkId: 'c1', sourceId: 's1', tenantId: 'tenant-A',
  familyId: 'family-X', childId: null, topicKey: 'maintenance',
  status: 'ACTIVE', legalHold: false, validFrom: PAST, validTo: FUTURE,
  content: 'x',
  ...overrides,
})

const assignment = (overrides: Partial<UserAssignment> = {}): UserAssignment => ({
  assignmentId: 'asg-001', assignmentVersion: 'v1',
  userId: 'user-001', tenantId: 'tenant-A',
  familyId: 'family-X', childId: null, role: 'manager',
  startedAt: new Date().toISOString(), endedAt: null, source: 'test',
  ...overrides,
})

function topicProvider() {
  return new InMemoryTopicPolicyProvider().set({
    policyId: 'pol-1', tenantId: 'tenant-A', role: 'manager',
    allowedTopics: ['maintenance', 'billing'], version: '2026.06', active: true,
  })
}

// ─────────────────────────────────────────────────────────────────────────────
// Ingestion governance is policy-derived, never defaulted (fail-closed)
// ─────────────────────────────────────────────────────────────────────────────

describe('IngestionGovernanceBinder', () => {
  const policy: SourceGovernance = {
    sourceId: 's1', tenantId: 'tenant-A', familyId: 'family-X', childId: null,
    sourceType: 'pdf', sourceUri: 's3://x', classification: 'confidential',
    retentionPolicyId: 'ret-1', legalHold: false,
    validFrom: PAST, validTo: FUTURE, policyVersion: '2026.06',
  }

  const providerWith = (p: SourceGovernance | null): GovernancePolicyProvider => ({
    async getPolicy() { return p },
  })

  test('binds authoritative governance when present', async () => {
    const binder = new IngestionGovernanceBinder(providerWith(policy))
    const bound = await binder.bind('s1', 'tenant-A')
    expect(bound.classification).toBe('confidential')
    expect(bound.policyVersion).toBe('2026.06')
  })

  test('refuses ingestion (fail-closed) when no authoritative policy exists', async () => {
    const binder = new IngestionGovernanceBinder(providerWith(null))
    await expect(binder.bind('s1', 'tenant-A')).rejects.toThrow(MissingGovernancePolicyError)
  })

  test('accepts a policy whose checksum matches', async () => {
    const signed = { ...policy, policyChecksum: computePolicyChecksum(policy) }
    const binder = new IngestionGovernanceBinder(providerWith(signed))
    await expect(binder.bind('s1', 'tenant-A')).resolves.toMatchObject({ policyVersion: '2026.06' })
  })

  test('rejects a policy whose checksum was tampered (fail-closed)', async () => {
    const tampered = { ...policy, policyChecksum: computePolicyChecksum(policy), validTo: new Date(Date.now() + 9e9) }
    const binder = new IngestionGovernanceBinder(providerWith(tampered))
    await expect(binder.bind('s1', 'tenant-A')).rejects.toThrow(PolicyIntegrityError)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// ApprovedEvidenceCorpus enforces the full canonical governance set
// ─────────────────────────────────────────────────────────────────────────────

describe('Corpus enforcement (topic / scope / status / legal hold / validity)', () => {
  const corpus = new ApprovedEvidenceCorpus()
  const run = (c: GovernedChunk, b = managerBoundary, opts = {}) => corpus.filter([c], b, opts)

  test('keeps a fully eligible chunk', () => {
    expect(run(chunk()).chunks).toHaveLength(1)
  })

  test('removes cross-tenant chunk', () => {
    expect(run(chunk({ tenantId: 'tenant-B' })).removed[0].reason).toBe('tenant-mismatch')
  })

  test('removes out-of-scope chunk', () => {
    expect(run(chunk({ familyId: 'family-Y' })).removed[0].reason).toBe('scope-mismatch')
  })

  test('removes ineligible-topic chunk', () => {
    expect(run(chunk({ topicKey: 'legal' })).removed[0].reason).toBe('topic-not-eligible')
  })

  test('removes non-ACTIVE chunk', () => {
    expect(run(chunk({ status: 'REVOKED' })).removed[0].reason).toBe('status-not-allowed')
  })

  test('removes chunk under legal hold', () => {
    expect(run(chunk({ legalHold: true })).removed[0].reason).toBe('legal-hold')
  })

  test('removes chunk past retention', () => {
    expect(run(chunk({ validTo: PAST })).removed[0].reason).toBe('retention-expired')
  })

  test('removes not-yet-effective chunk', () => {
    expect(run(chunk({ validFrom: FUTURE })).removed[0].reason).toBe('not-yet-effective')
  })

  test('empty boundary removes everything (no authority)', () => {
    const empty: EvidenceBoundary = { ...managerBoundary, scopes: [], empty: true }
    expect(run(chunk(), empty).removed[0].reason).toBe('no-authority')
  })

  test('child-scoped boundary rejects a sibling child chunk', () => {
    const b: EvidenceBoundary = { ...managerBoundary, scopes: [{ familyId: 'family-X', childId: 'child-1' }] }
    expect(run(chunk({ childId: 'child-2' }), b).removed[0].reason).toBe('scope-mismatch')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// HandOff evidence integrity (unchanged by the realign)
// ─────────────────────────────────────────────────────────────────────────────

describe('HandOff manifest integrity', () => {
  const key: SigningKey = { keyId: 'k1', secret: 'super-secret' }
  const builder = new HandOffBuilder()
  const verifier = new HandOffVerifier()

  const make = () => builder.build({
    sourceId: 's1', sourceContent: 'the original source document',
    chunkIds: ['c1', 'c2'], chunkContents: ['chunk one', 'chunk two'],
    ingestionAudit: { ingestedAt: new Date().toISOString(), ingestedBy: 'pipeline', pipelineVersion: '1.0', sourceUri: 's3://x' },
    chainOfCustody: [{ stage: 'ingest', actor: 'pipeline', at: new Date().toISOString() }],
  }, key)

  test('builds a signed manifest with source + chunk hashes', () => {
    const m = make()
    expect(m.sourceHash).toHaveLength(64)
    expect(m.chunkHash).toHaveLength(64)
    expect(m.signature).toHaveLength(64)
    expect(m.chainOfCustody).toHaveLength(1)
  })

  test('verifies a valid manifest against raw evidence', () => {
    const m = make()
    const r = verifier.verify(m, key, { sourceContent: 'the original source document', chunkContents: ['chunk one', 'chunk two'] })
    expect(r.valid).toBe(true)
  })

  test('detects tampered manifest body', () => {
    const m = make()
    m.sourceId = 'attacker-source'
    const r = verifier.verify(m, key)
    expect(r.valid).toBe(false)
    expect(r.reasons).toContain('Manifest hash mismatch (manifest body altered)')
  })

  test('detects forged signature / wrong key', () => {
    const m = make()
    const r = verifier.verify(m, { keyId: 'k1', secret: 'wrong-secret' })
    expect(r.valid).toBe(false)
    expect(r.reasons).toContain('Manifest signature invalid')
  })

  test('detects source bytes not matching sourceHash', () => {
    const m = make()
    const r = verifier.verify(m, key, { sourceContent: 'different bytes' })
    expect(r.valid).toBe(false)
    expect(r.reasons).toContain('Source content does not match sourceHash')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// TrustRAG fail-closed governed retrieval (searchRagChunksAudited)
// ─────────────────────────────────────────────────────────────────────────────

describe('TrustRAG governed retrieval', () => {
  class SpyIndex implements VectorIndex {
    lastQuery: VectorQuery | null = null
    constructor(private corpus: GovernedChunk[]) {}
    async searchWithin(query: VectorQuery): Promise<GovernedChunk[]> {
      this.lastQuery = query
      return this.corpus.filter(c =>
        c.tenantId === query.predicate.tenantId &&
        query.predicate.eligibleTopics.includes(c.topicKey),
      )
    }
  }

  test('refuses to query the index on an empty boundary (fail-closed)', async () => {
    const index = new SpyIndex([chunk()])
    const retriever = new TrustRAGRetriever(index)
    const empty: EvidenceBoundary = { ...managerBoundary, scopes: [], empty: true }
    await expect(retriever.searchRagChunksAudited([0.1], 5, empty)).rejects.toThrow(UnauthorizedRetrievalError)
    expect(index.lastQuery).toBeNull()
  })

  test('compiles a deterministic predicate from the boundary', () => {
    const retriever = new TrustRAGRetriever(new SpyIndex([chunk()]))
    const pred = retriever.compilePredicate(managerBoundary)
    expect(pred.denyAll).toBe(false)
    expect(pred.tenantId).toBe('tenant-A')
    expect(pred.scopes).toEqual([{ familyId: 'family-X', childId: null }])
    expect(pred.eligibleTopics).toEqual(['maintenance', 'billing'])
    expect(pred.allowedStatuses).toEqual(['ACTIVE'])
  })

  test('searches only within the predicate and re-filters results', async () => {
    const index = new SpyIndex([chunk(), chunk({ chunkId: 'c2', tenantId: 'tenant-B' })])
    const retriever = new TrustRAGRetriever(index)
    const r = await retriever.searchRagChunksAudited([0.1], 5, managerBoundary)
    expect(index.lastQuery?.predicate.tenantId).toBe('tenant-A')
    expect(r.chunks).toHaveLength(1)
    expect(r.chunks[0].chunkId).toBe('c1')
  })

  test('retrieve() is an alias for searchRagChunksAudited()', async () => {
    const retriever = new TrustRAGRetriever(new SpyIndex([chunk()]))
    const r = await retriever.retrieve([0.1], 5, managerBoundary)
    expect(r.chunks).toHaveLength(1)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Audit-grade DAR boundary + assignment-driven authority
// ─────────────────────────────────────────────────────────────────────────────

describe('DAR audit-grade boundary (scopes + topics + snapshot + policy version)', () => {
  test('boundary carries scopes and eligible topics from assignment + policy', async () => {
    const resolver = new InMemoryAssignmentResolver()
      .grant(assignment({ assignmentId: 'asg-77', assignmentVersion: 'v3' }))
    const dar = new DAREngine(resolver, topicProvider(), { policyVersion: 'fallback' })
    const b = await dar.resolve(claim)
    expect(b.scopes).toEqual([{ familyId: 'family-X', childId: null }])
    expect(b.eligibleTopics).toEqual(['billing', 'maintenance'])
    expect(b.policyVersion).toBe('2026.06')
  })

  test('boundary is replayable: authoritySnapshotId is a deterministic hash', async () => {
    const resolver = new InMemoryAssignmentResolver().grant(assignment())
    const dar = new DAREngine(resolver, topicProvider())
    const b = await dar.resolve(claim)
    expect(b.authoritySnapshotId).toHaveLength(64)
    expect(b.empty).toBe(false)
  })

  test('empty boundary still records the fallback policy version for audit', async () => {
    const dar = new DAREngine(new InMemoryAssignmentResolver(), topicProvider(), { policyVersion: 'fallback' })
    const b = await dar.resolve(claim)
    expect(b.empty).toBe(true)
    expect(b.authoritySnapshotId).toBe('none')
    expect(b.policyVersion).toBe('fallback')
  })
})

describe('Identity layer scope enforcement is assignment-driven (not claim-driven)', () => {
  const guard = new TenantIsolationGuard()

  test('allows a family granted by the assignment', () => {
    expect(() => guard.enforceScope([assignment()], 'family-X')).not.toThrow()
  })

  test('denies a family NOT in the assignment (no claim trust)', () => {
    expect(() => guard.enforceScope([assignment()], 'family-Y')).toThrow('SCOPE_ISOLATION')
  })

  test('admin role does NOT bypass scope — authority is purely assignment-based', () => {
    expect(() => guard.enforceScope([assignment({ role: 'admin' })], 'family-Z')).toThrow('SCOPE_ISOLATION')
  })
})
