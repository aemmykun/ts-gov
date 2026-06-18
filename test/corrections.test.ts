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
  PolicyIntegrityError,
  computePolicyChecksum,
} from '../src/policy/GovernancePolicyProvider'
import { DocumentPolicy } from '../src/policy/types'
import { HandOffBuilder } from '../src/handoff/HandOffBuilder'
import { HandOffVerifier } from '../src/handoff/HandOffVerifier'
import { SigningKey } from '../src/handoff/HandOffSigner'
import { TrustRAGRetriever, UnauthorizedRetrievalError } from '../src/trustrag/TrustRAGRetriever'
import { VectorIndex, VectorQuery } from '../src/trustrag/types'
import { TenantIsolationGuard } from '../src/identity/TenantIsolationGuard'
import { UserAssignment } from '../src/assignments/types'
import { roleMeetsThreshold } from '../src/identity/roles'

const claim: TenantClaim = {
  userId: 'user-001', tenantId: 'tenant-A', provider: 'entra', verifiedAt: Date.now(),
}

const managerBoundary: EvidenceBoundary = {
  tenantIds: ['tenant-A'], organisationIds: [], scopeIds: [],
  familyIds: ['family-X'], allFamilies: false,
  allowedStatuses: ['active'], allowedRoles: ['manager'],
  classificationLevel: 'restricted', sensitivityLevel: 'critical',
  authoritySnapshotId: 'asg-001@v1', policyVersion: '4.2.0',
  effectiveAt: new Date().toISOString(), computedAt: new Date().toISOString(),
  empty: false,
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
    policyVersion: '4.2.0',
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

  test('carries an authoritative policyVersion', async () => {
    const binder = new IngestionGovernanceBinder(providerWith(policy))
    const bound = await binder.bind('s1', 'tenant-A')
    expect(bound.policyVersion).toBe('4.2.0')
  })

  test('accepts a policy whose checksum matches', async () => {
    const signed = { ...policy, policyChecksum: computePolicyChecksum(policy) }
    const binder = new IngestionGovernanceBinder(providerWith(signed))
    await expect(binder.bind('s1', 'tenant-A')).resolves.toMatchObject({ policyVersion: '4.2.0' })
  })

  test('rejects a policy whose checksum was tampered (fail-closed)', async () => {
    const tampered = { ...policy, policyChecksum: computePolicyChecksum(policy), retainUntil: new Date(Date.now() + 9e9) }
    const binder = new IngestionGovernanceBinder(providerWith(tampered))
    await expect(binder.bind('s1', 'tenant-A')).rejects.toThrow(PolicyIntegrityError)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Correction #3 — ApprovedEvidenceCorpus enforces the full governance set
// ─────────────────────────────────────────────────────────────────────────────

describe('Correction #3 — expanded corpus enforcement', () => {
  const corpus = new ApprovedEvidenceCorpus()
  const run = (c: GovernedChunk, b = managerBoundary, opts = {}) =>
    corpus.filter([c], b, opts)

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
    const b: EvidenceBoundary = { ...managerBoundary, classificationLevel: 'internal' }
    const r = run(chunk({ governance: { status: 'active', allowedRoles: ['manager'], visibility: 'tenant', classification: 'restricted' } }), b)
    expect(r.removed[0].reason).toBe('classification-exceeds-boundary')
  })

  test('classification comparison is case-insensitive (enum-normalized)', () => {
    const b: EvidenceBoundary = { ...managerBoundary, classificationLevel: 'confidential' }
    // 'CONFIDENTIAL' must be treated as 'confidential', not as an unknown value.
    const r = run(chunk({ governance: { status: 'active', allowedRoles: ['manager'], visibility: 'tenant', classification: 'CONFIDENTIAL' as never } }), b)
    expect(r.chunks).toHaveLength(1)
  })

  test('enforces sensitivity ceiling', () => {
    const b: EvidenceBoundary = { ...managerBoundary, sensitivityLevel: 'low' }
    const r = run(chunk({ governance: { status: 'active', allowedRoles: ['manager'], visibility: 'tenant', sensitivity: 'critical' } }), b)
    expect(r.removed[0].reason).toBe('sensitivity-exceeds-boundary')
  })

  test('enforces organisation boundary', () => {
    const b: EvidenceBoundary = { ...managerBoundary, organisationIds: ['org-1'] }
    const r = run(chunk({ organisationId: 'org-2' }), b)
    expect(r.removed[0].reason).toBe('organisation-mismatch')
  })

  test('enforces scope boundary', () => {
    const b: EvidenceBoundary = { ...managerBoundary, scopeIds: ['scope-1'] }
    const r = run(chunk({ scopeId: 'scope-9' }), b)
    expect(r.removed[0].reason).toBe('scope-mismatch')
  })

  test('strict mode rejects chunk missing required governance metadata', () => {
    // org/scope present so the first missing dimension surfaced is retention.
    const r = run(chunk({ organisationId: 'org-1', scopeId: 'scope-1' }), managerBoundary, { strict: true })
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
        (query.predicate.allFamilies || query.predicate.familyIds.includes(c.familyId)),
      )
    }
  }

  test('refuses to query the index on an empty boundary (fail-closed)', async () => {
    const index = new SpyIndex([chunk()])
    const retriever = new TrustRAGRetriever(index)
    const empty: EvidenceBoundary = { ...managerBoundary, tenantIds: [], empty: true }
    await expect(retriever.retrieve([0.1], 5, empty)).rejects.toThrow(UnauthorizedRetrievalError)
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
    const r = await retriever.retrieve([0.1], 5, managerBoundary)
    expect(index.lastQuery?.predicate.tenantIds).toEqual(['tenant-A'])
    expect(r.chunks).toHaveLength(1)
    expect(r.chunks[0].chunkId).toBe('c1')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Gaps 1/3/4 — organisation/scope boundaries + audit-grade replay provenance
// ─────────────────────────────────────────────────────────────────────────────

describe('DAR audit-grade boundary (org/scope + snapshot + policy version)', () => {
  const resolver = new InMemoryAssignmentResolver().grant({
    assignmentId: 'asg-77', assignmentVersion: 'v3',
    userId: 'user-001', tenantId: 'tenant-A',
    organisationIds: ['org-1', 'org-2'], scopeIds: ['scope-9'], familyIds: ['family-X'],
    role: 'manager', classificationClearance: 'confidential', sensitivityClearance: 'high',
    source: 'scim', assignedAt: new Date().toISOString(),
  })
  const dar = new DAREngine(resolver, { policyVersion: '4.2.0' })

  test('boundary carries organisation and scope membership from the assignment', async () => {
    const b = await dar.resolve(claim)
    expect(b.organisationIds).toEqual(['org-1', 'org-2'])
    expect(b.scopeIds).toEqual(['scope-9'])
  })

  test('boundary clearance ceilings come from the assignment (not the claim)', async () => {
    const b = await dar.resolve(claim)
    expect(b.classificationLevel).toBe('confidential')
    expect(b.sensitivityLevel).toBe('high')
  })

  test('boundary is replayable: authoritySnapshotId + policyVersion are stamped', async () => {
    const b = await dar.resolve(claim)
    expect(b.authoritySnapshotId).toBe('asg-77@v3')
    expect(b.policyVersion).toBe('4.2.0')
  })

  test('empty boundary still records the policy version for audit', async () => {
    const b = await new DAREngine(new InMemoryAssignmentResolver(), { policyVersion: '4.2.0' }).resolve(claim)
    expect(b.empty).toBe(true)
    expect(b.authoritySnapshotId).toBe('none')
    expect(b.policyVersion).toBe('4.2.0')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Authority hardening — identity ≠ authority + documented role threshold model
// ─────────────────────────────────────────────────────────────────────────────

describe('Identity layer family enforcement is assignment-driven', () => {
  const guard = new TenantIsolationGuard()
  const assignment: UserAssignment = {
    assignmentId: 'asg-1', assignmentVersion: 'v1',
    userId: 'user-001', tenantId: 'tenant-A',
    organisationIds: ['org-1'], scopeIds: [], familyIds: ['family-X'],
    role: 'manager', classificationClearance: 'restricted', sensitivityClearance: 'critical',
    source: 'test', assignedAt: new Date().toISOString(),
  }

  test('allows a family granted by the assignment', () => {
    expect(() => guard.enforceFamily(assignment, 'family-X')).not.toThrow()
  })

  test('denies a family NOT in the assignment (no claim trust)', () => {
    expect(() => guard.enforceFamily(assignment, 'family-Y')).toThrow('FAMILY_ISOLATION')
  })

  test('owner assignment is tenant-wide', () => {
    expect(() => guard.enforceFamily({ ...assignment, role: 'owner' }, 'any-family')).not.toThrow()
  })
})

describe('roleMeetsThreshold documents minimum-threshold (NOT OR) semantics', () => {
  test("['owner','admin','manager'] means manager-and-above", () => {
    expect(roleMeetsThreshold('manager', ['owner', 'admin', 'manager'])).toBe(true)
    expect(roleMeetsThreshold('member',  ['owner', 'admin', 'manager'])).toBe(false)
  })

  test("['viewer','admin'] means viewer-and-above (the documented gotcha)", () => {
    // Despite listing 'admin', a viewer satisfies it because viewer is the
    // lowest threshold in the set. This is by design and is documented.
    expect(roleMeetsThreshold('viewer', ['viewer', 'admin'])).toBe(true)
  })

  test('unknown role is denied (fail-closed); owner is a superuser', () => {
    expect(roleMeetsThreshold('superadmin', ['viewer'])).toBe(false)
    expect(roleMeetsThreshold('owner', [])).toBe(true)
  })
})
