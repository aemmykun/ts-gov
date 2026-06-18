/**
 * TenantSage — Governance Correction Test Suite
 * Proves the 5 governance-model corrections requested in review.
 */

import { DAREngine } from '../src/dar/DAREngine'
import { EvidenceBoundary } from '../src/dar/types'
import { InMemoryAssignmentResolver } from '../src/assignments/InMemoryAssignmentResolver'
import { ApprovedEvidenceCorpus, GovernedChunk } from '../src/runtime/ApprovedEvidenceCorpus'
import { TenantClaim } from '../src/identity/types'
import {
  IngestionGovernanceBinder,
  GovernancePolicyProvider,
  MissingGovernancePolicyError,
} from '../src/policy/GovernancePolicyProvider'
import { DocumentPolicy } from '../src/policy/types'
import { HandOffBuilder } from '../src/handoff/HandOffBuilder'
import { HandOffVerifier } from '../src/handoff/HandOffVerifier'
import { SigningKey } from '../src/handoff/HandOffSigner'
import { TrustRAGRetriever, UnauthorizedRetrievalError } from '../src/trustrag/TrustRAGRetriever'
import { VectorIndex, VectorQuery } from '../src/trustrag/types'

const claim: TenantClaim = {
  userId: 'user-001', tenantId: 'tenant-A', familyId: 'family-X',
  role: 'manager', orgUnit: 'eng', provider: 'entra', verifiedAt: Date.now(),
}

const managerBoundary: EvidenceBoundary = {
  tenantIds: ['tenant-A'], familyIds: ['family-X'],
  allowedStatuses: ['active'], allowedRoles: ['manager'],
  effectiveAt: new Date().toISOString(), computedAt: new Date().toISOString(),
}

const chunk = (overrides: Partial<GovernedChunk> = {}): GovernedChunk => ({
  chunkId: 'c1', sourceId: 's1', tenantId: 'tenant-A', familyId: 'family-X',
  content: 'x',
  governance: { status: 'active', allowedRoles: ['manager'], visibility: 'tenant' },
  ...overrides,
})

// ─────────────────────────────────────────────────────────────────────────────
// Correction #2 — governance metadata is policy-derived, never defaulted
// ─────────────────────────────────────────────────────────────────────────────

describe('Correction #2 — IngestionGovernanceBinder', () => {
  const policy: DocumentPolicy = {
    documentId: 'doc-1', tenantId: 'tenant-A', familyId: 'family-X',
    retainUntil: new Date(Date.now() + 1e9), legalHold: false,
    allowedRoles: ['manager'], effectiveFrom: new Date(Date.now() - 1e6),
    effectiveTo: new Date(Date.now() + 1e9), status: 'active',
  }

  const providerWith = (p: DocumentPolicy | null): GovernancePolicyProvider => ({
    async getPolicy() { return p },
  })

  test('binds authoritative policy when present', async () => {
    const binder = new IngestionGovernanceBinder(providerWith(policy))
    const bound = await binder.bind('s1', 'tenant-A')
    expect(bound.allowedRoles).toEqual(['manager'])
  })

  test('refuses ingestion (fail-closed) when no authoritative policy exists', async () => {
    const binder = new IngestionGovernanceBinder(providerWith(null))
    await expect(binder.bind('s1', 'tenant-A')).rejects.toThrow(MissingGovernancePolicyError)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Correction #3 — ApprovedEvidenceCorpus enforces the full governance set
// ─────────────────────────────────────────────────────────────────────────────

describe('Correction #3 — expanded corpus enforcement', () => {
  const corpus = new ApprovedEvidenceCorpus()
  const run = (c: GovernedChunk, b = managerBoundary, opts = {}) =>
    corpus.filter([c], claim, b, opts)

  test('removes chunk under legal hold', () => {
    const r = run(chunk({ governance: { status: 'active', allowedRoles: ['manager'], visibility: 'tenant', legalHold: true } }))
    expect(r.chunks).toHaveLength(0)
    expect(r.removed[0].reason).toBe('legal-hold')
  })

  test('removes chunk past retention', () => {
    const r = run(chunk({ governance: { status: 'active', allowedRoles: ['manager'], visibility: 'tenant', retainUntil: new Date(Date.now() - 1000) } }))
    expect(r.removed[0].reason).toBe('retention-expired')
  })

  test('removes not-yet-effective chunk', () => {
    const r = run(chunk({ governance: {
      status: 'active', allowedRoles: ['manager'], visibility: 'tenant',
      effectiveFrom: new Date(Date.now() + 1e6), effectiveTo: new Date(Date.now() + 1e9),
    } }))
    expect(r.removed[0].reason).toBe('not-yet-effective')
  })

  test('removes past-effective chunk', () => {
    const r = run(chunk({ governance: {
      status: 'active', allowedRoles: ['manager'], visibility: 'tenant',
      effectiveFrom: new Date(Date.now() - 1e9), effectiveTo: new Date(Date.now() - 1000),
    } }))
    expect(r.removed[0].reason).toBe('past-effective')
  })

  test('removes inactive lifecycle chunk (superseded)', () => {
    const r = run(chunk({ governance: { status: 'active', allowedRoles: ['manager'], visibility: 'tenant', lifecycle: 'superseded' } }))
    expect(r.removed[0].reason).toBe('lifecycle-inactive')
  })

  test('enforces classification ceiling', () => {
    const b: EvidenceBoundary = { ...managerBoundary, maxClassification: 'internal' }
    const r = run(chunk({ governance: { status: 'active', allowedRoles: ['manager'], visibility: 'tenant', classification: 'restricted' } }), b)
    expect(r.removed[0].reason).toBe('classification-exceeds-boundary')
  })

  test('enforces sensitivity ceiling', () => {
    const b: EvidenceBoundary = { ...managerBoundary, maxSensitivity: 'low' }
    const r = run(chunk({ governance: { status: 'active', allowedRoles: ['manager'], visibility: 'tenant', sensitivity: 'critical' } }), b)
    expect(r.removed[0].reason).toBe('sensitivity-exceeds-boundary')
  })

  test('strict mode rejects chunk missing required governance metadata', () => {
    const r = run(chunk(), managerBoundary, { strict: true })
    expect(r.chunks).toHaveLength(0)
    expect(r.removed[0].reason).toBe('retention-missing')
  })

  test('empty boundary removes everything (no authority)', () => {
    const empty: EvidenceBoundary = { ...managerBoundary, tenantIds: [], empty: true }
    const r = run(chunk(), empty)
    expect(r.chunks).toHaveLength(0)
    expect(r.removed[0].reason).toBe('no-authority')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Correction #4 — HandOff evidence integrity
// ─────────────────────────────────────────────────────────────────────────────

describe('Correction #4 — HandOff manifest integrity', () => {
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
// Correction #5 — TrustRAG fail-closed governed retrieval
// ─────────────────────────────────────────────────────────────────────────────

describe('Correction #5 — TrustRAG governed retrieval', () => {
  // Spy index that records the predicate it was queried with.
  class SpyIndex implements VectorIndex {
    lastQuery: VectorQuery | null = null
    constructor(private corpus: GovernedChunk[]) {}
    async searchWithin(query: VectorQuery): Promise<GovernedChunk[]> {
      this.lastQuery = query
      // A compliant index honours the predicate.
      return this.corpus.filter(c =>
        query.predicate.tenantIds.includes(c.tenantId) &&
        (query.predicate.familyIds.includes('*') || query.predicate.familyIds.includes(c.familyId)),
      )
    }
  }

  test('refuses to query the index on an empty boundary (fail-closed)', async () => {
    const index = new SpyIndex([chunk()])
    const retriever = new TrustRAGRetriever(index)
    const empty: EvidenceBoundary = { ...managerBoundary, tenantIds: [], empty: true }
    await expect(retriever.retrieve([0.1], 5, claim, empty)).rejects.toThrow(UnauthorizedRetrievalError)
    expect(index.lastQuery).toBeNull() // index was never touched
  })

  test('compiles a deterministic predicate from the boundary', async () => {
    const index = new SpyIndex([chunk()])
    const retriever = new TrustRAGRetriever(index)
    const pred = retriever.compilePredicate(managerBoundary)
    expect(pred.denyAll).toBe(false)
    expect(pred.tenantIds).toEqual(['tenant-A'])
    expect(pred.familyIds).toEqual(['family-X'])
    expect(pred.allowedStatuses).toEqual(['active'])
  })

  test('searches only within the predicate and re-filters results', async () => {
    const index = new SpyIndex([
      chunk(),                              // valid
      chunk({ chunkId: 'c2', tenantId: 'tenant-B' }), // wrong tenant
    ])
    const retriever = new TrustRAGRetriever(index)
    const r = await retriever.retrieve([0.1], 5, claim, managerBoundary)
    expect(index.lastQuery?.predicate.tenantIds).toEqual(['tenant-A'])
    expect(r.chunks).toHaveLength(1)
    expect(r.chunks[0].chunkId).toBe('c1')
  })
})
