/**
 * TenantSage — governance library test suite (canonical SQL-schema model).
 * Hierarchy tenant → family → child; topic-based authorization;
 * staff/supervisor/manager/admin; ACTIVE/REVOKED/EXPIRED; ALLOW/DENY ledger.
 */

import { TenantIsolationGuard }  from '../src/identity/TenantIsolationGuard'
import { roleLevel, roleAtLeast, isRole } from '../src/identity/roles'
import { PolicyEngine }          from '../src/policy/PolicyEngine'
import { TenantBoundaryCheck }   from '../src/policy/checks/TenantBoundaryCheck'
import { ScopeCheck }            from '../src/policy/checks/ScopeCheck'
import { TopicPermissionCheck }  from '../src/policy/checks/TopicPermissionCheck'
import { StatusCheck }           from '../src/policy/checks/StatusCheck'
import { RetentionCheck }        from '../src/policy/checks/RetentionCheck'
import { LegalHoldCheck }        from '../src/policy/checks/LegalHoldCheck'
import { EffectiveDateCheck }    from '../src/policy/checks/EffectiveDateCheck'
import { AuditLockService }      from '../src/policy/AuditLockService'
import { BlockBuilder }          from '../src/ledger/BlockBuilder'
import { EvidenceLedger }        from '../src/ledger/EvidenceLedger'
import { ChainVerifier }         from '../src/ledger/ChainVerifier'
import { InMemoryLedgerStore }   from '../src/ledger/LedgerStore'
import { DAREngine }             from '../src/dar/DAREngine'
import { InMemoryAssignmentResolver } from '../src/assignments/InMemoryAssignmentResolver'
import { InMemoryTopicPolicyProvider } from '../src/policy/TopicPolicyProvider'
import { UserAssignment }        from '../src/assignments/types'
import { EvidenceBoundary }      from '../src/dar/types'
import { ApprovedEvidenceCorpus, GovernedChunk } from '../src/runtime/ApprovedEvidenceCorpus'
import { TenantClaim }           from '../src/identity/types'
import { PolicyContext, PolicyResource } from '../src/policy/types'

// ─── FIXTURES ─────────────────────────────────────────────────────────────────

const PAST   = new Date(Date.now() - 86_400_000)
const FUTURE = new Date(Date.now() + 86_400_000 * 365)

const mockClaim: TenantClaim = {
  userId:     'user-001',
  tenantId:   'tenant-A',
  provider:   'entra',
  verifiedAt: Date.now(),
}

const mockAssignment = (overrides: Partial<UserAssignment> = {}): UserAssignment => ({
  assignmentId:      'asg-001',
  assignmentVersion: 'v1',
  userId:            'user-001',
  tenantId:          'tenant-A',
  familyId:          'family-X',
  childId:           null,
  role:              'manager',
  startedAt:         new Date().toISOString(),
  endedAt:           null,
  source:            'test',
  ...overrides,
})

// A resolved authority boundary granting family-X + topics maintenance/billing.
const mockBoundary = (overrides: Partial<EvidenceBoundary> = {}): EvidenceBoundary => ({
  tenantId:            'tenant-A',
  scopes:              [{ familyId: 'family-X', childId: null }],
  eligibleTopics:      ['billing', 'maintenance'],
  allowedStatuses:     ['ACTIVE'],
  roleLevel:           3,
  authoritySnapshotId: 'snap-1',
  policyVersion:       '2026.06',
  effectiveAt:         new Date().toISOString(),
  computedAt:          new Date().toISOString(),
  empty:               false,
  ...overrides,
})

const mockResource = (overrides: Partial<PolicyResource> = {}): PolicyResource => ({
  resourceId:    'chunk-001',
  tenantId:      'tenant-A',
  familyId:      'family-X',
  childId:       null,
  topicKey:      'maintenance',
  status:        'ACTIVE',
  legalHold:     false,
  validFrom:     PAST,
  validTo:       FUTURE,
  policyVersion: '2026.06',
  ...overrides,
})

const ctx = (resource: Partial<PolicyResource> = {}, boundary: Partial<EvidenceBoundary> = {}): PolicyContext => ({
  claim:       mockClaim,
  boundary:    mockBoundary(boundary),
  resource:    mockResource(resource),
  requestedAt: new Date(),
})

const mockChunk = (overrides: Partial<GovernedChunk> = {}): GovernedChunk => ({
  chunkId:   'c1',
  sourceId:  's1',
  tenantId:  'tenant-A',
  familyId:  'family-X',
  childId:   null,
  topicKey:  'maintenance',
  status:    'ACTIVE',
  legalHold: false,
  validFrom: PAST,
  validTo:   FUTURE,
  content:   'chunk content',
  ...overrides,
})

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 1 — IDENTITY
// ─────────────────────────────────────────────────────────────────────────────

describe('roles', () => {
  test('canonical ordering staff < supervisor < manager < admin', () => {
    expect(roleLevel('staff')).toBeLessThan(roleLevel('supervisor'))
    expect(roleLevel('supervisor')).toBeLessThan(roleLevel('manager'))
    expect(roleLevel('manager')).toBeLessThan(roleLevel('admin'))
  })

  test('unknown role resolves to level 0 (fail-closed)', () => {
    expect(roleLevel('owner')).toBe(0)
    expect(roleLevel(undefined)).toBe(0)
    expect(isRole('owner')).toBe(false)
    expect(isRole('admin')).toBe(true)
  })

  test('roleAtLeast respects hierarchy and fails closed on unknown', () => {
    expect(roleAtLeast('manager', 'supervisor')).toBe(true)
    expect(roleAtLeast('staff', 'manager')).toBe(false)
    expect(roleAtLeast('nope', 'staff')).toBe(false)
  })
})

describe('Layer 1 — TenantIsolationGuard', () => {
  const guard = new TenantIsolationGuard()

  test('allows same-tenant access', () => {
    expect(() => guard.enforce(mockClaim, 'tenant-A')).not.toThrow()
  })

  test('blocks cross-tenant access', () => {
    expect(() => guard.enforce(mockClaim, 'tenant-B')).toThrow('TENANT_ISOLATION')
  })

  test('whitespace-padded tenant id does not bypass', () => {
    expect(() => guard.enforce(mockClaim, ' tenant-A ')).not.toThrow()
  })

  test('blocks empty requestedTenantId', () => {
    expect(() => guard.enforce(mockClaim, '')).toThrow('must not be empty')
  })

  test('allows same-family access via family-level assignment', () => {
    expect(() => guard.enforceScope([mockAssignment()], 'family-X')).not.toThrow()
  })

  test('blocks cross-family access', () => {
    expect(() => guard.enforceScope([mockAssignment()], 'family-Y')).toThrow('SCOPE_ISOLATION')
  })

  test('child-scoped assignment authorises only that child', () => {
    const asg = [mockAssignment({ childId: 'child-1' })]
    expect(() => guard.enforceScope(asg, 'family-X', 'child-1')).not.toThrow()
    expect(() => guard.enforceScope(asg, 'family-X', 'child-2')).toThrow('SCOPE_ISOLATION')
  })

  test('family-level assignment authorises any child', () => {
    expect(() => guard.enforceScope([mockAssignment()], 'family-X', 'child-9')).not.toThrow()
  })

  test('blocks empty requestedFamilyId', () => {
    expect(() => guard.enforceScope([mockAssignment()], '')).toThrow('must not be empty')
  })

  test('no assignments denies all scope access', () => {
    expect(() => guard.enforceScope([], 'family-X')).toThrow('SCOPE_ISOLATION')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 2 — POLICY GATES
// ─────────────────────────────────────────────────────────────────────────────

describe('Layer 2 — TenantBoundaryCheck', () => {
  const check = new TenantBoundaryCheck()
  test('passes same-tenant resource', () => {
    expect(check.run(ctx()).passed).toBe(true)
  })
  test('fails cross-tenant resource', () => {
    const r = check.run(ctx({ tenantId: 'tenant-B' }))
    expect(r.passed).toBe(false)
    expect(r.failedAt).toBe('tenant_boundary')
  })
})

describe('Layer 2 — ScopeCheck', () => {
  const check = new ScopeCheck()
  test('passes in-scope resource', () => {
    expect(check.run(ctx()).passed).toBe(true)
  })
  test('fails out-of-family resource', () => {
    const r = check.run(ctx({ familyId: 'family-Y' }))
    expect(r.passed).toBe(false)
    expect(r.failedAt).toBe('scope')
  })
  test('family-level grant covers child resource', () => {
    expect(check.run(ctx({ childId: 'child-7' })).passed).toBe(true)
  })
  test('child-scoped grant rejects sibling child', () => {
    const r = check.run(ctx(
      { childId: 'child-2' },
      { scopes: [{ familyId: 'family-X', childId: 'child-1' }] },
    ))
    expect(r.passed).toBe(false)
  })
})

describe('Layer 2 — TopicPermissionCheck', () => {
  const check = new TopicPermissionCheck()
  test('passes eligible topic', () => {
    expect(check.run(ctx({ topicKey: 'billing' })).passed).toBe(true)
  })
  test('fails ineligible topic', () => {
    const r = check.run(ctx({ topicKey: 'legal' }))
    expect(r.passed).toBe(false)
    expect(r.failedAt).toBe('topic_permission')
  })
  test('empty eligible topics denies everything (fail-closed)', () => {
    const r = check.run(ctx({}, { eligibleTopics: [] }))
    expect(r.passed).toBe(false)
  })
})

describe('Layer 2 — StatusCheck', () => {
  const check = new StatusCheck()
  test('passes ACTIVE', () => {
    expect(check.run(ctx({ status: 'ACTIVE' })).passed).toBe(true)
  })
  test('fails REVOKED', () => {
    const r = check.run(ctx({ status: 'REVOKED' }))
    expect(r.passed).toBe(false)
    expect(r.failedAt).toBe('status')
  })
  test('fails EXPIRED', () => {
    expect(check.run(ctx({ status: 'EXPIRED' })).passed).toBe(false)
  })
})

describe('Layer 2 — RetentionCheck', () => {
  const check = new RetentionCheck()
  test('passes within retention window', () => {
    expect(check.run(ctx()).passed).toBe(true)
  })
  test('passes null validTo (retain indefinitely)', () => {
    expect(check.run(ctx({ validTo: null })).passed).toBe(true)
  })
  test('fails expired retention', () => {
    const r = check.run(ctx({ validTo: new Date(Date.now() - 1000) }))
    expect(r.passed).toBe(false)
    expect(r.failedAt).toBe('retention')
  })
  test('fails invalid validTo (fail-closed)', () => {
    const r = check.run(ctx({ validTo: new Date('not-a-date') }))
    expect(r.passed).toBe(false)
    expect(r.failedAt).toBe('retention')
  })
})

describe('Layer 2 — LegalHoldCheck', () => {
  const check = new LegalHoldCheck()
  test('passes when no legal hold', () => {
    expect(check.run(ctx({ legalHold: false })).passed).toBe(true)
  })
  test('fails and sets auditLocked when hold is active', () => {
    const r = check.run(ctx({ legalHold: true, legalHoldReason: 'Litigation 2026' }))
    expect(r.passed).toBe(false)
    expect(r.failedAt).toBe('legal_hold')
    expect(r.auditLocked).toBe(true)
    expect(r.reason).toContain('Litigation 2026')
  })
  test('truthy string is not a hold (strict boolean)', () => {
    expect(check.run(ctx({ legalHold: ('true' as unknown as boolean) })).passed).toBe(true)
  })
  test('flags missing reason for compliance review', () => {
    const r = check.run(ctx({ legalHold: true, legalHoldReason: undefined }))
    expect(r.reason).toContain('compliance review')
  })
})

describe('Layer 2 — EffectiveDateCheck', () => {
  const check = new EffectiveDateCheck()
  test('passes effective resource', () => {
    expect(check.run(ctx()).passed).toBe(true)
  })
  test('fails not-yet-effective resource', () => {
    const r = check.run(ctx({ validFrom: new Date(Date.now() + 86_400_000) }))
    expect(r.passed).toBe(false)
    expect(r.failedAt).toBe('effective_date')
  })
  test('fails invalid validFrom (fail-closed)', () => {
    const r = check.run(ctx({ validFrom: new Date('nope') }))
    expect(r.passed).toBe(false)
    expect(r.failedAt).toBe('effective_date')
  })
})

describe('Layer 2 — PolicyEngine (ordered gates)', () => {
  let auditLock: AuditLockService
  let engine: PolicyEngine
  beforeEach(() => {
    auditLock = new AuditLockService()
    engine = new PolicyEngine(auditLock)
  })

  test('ALLOW when every gate passes', async () => {
    expect((await engine.evaluate(ctx())).passed).toBe(true)
  })

  test('tenant gate short-circuits first', async () => {
    const r = await engine.evaluate(ctx({ tenantId: 'tenant-B', topicKey: 'legal' }))
    expect(r.failedAt).toBe('tenant_boundary')
  })

  test('legal hold fires an audit lock with provenance', async () => {
    const c = ctx({ legalHold: true, legalHoldReason: 'hold' })
    c.provenance = { authoritySnapshotId: 'snap-1', boundaryHash: 'bh' }
    const r = await engine.evaluate(c)
    expect(r.failedAt).toBe('legal_hold')
    const locks = auditLock.list()
    expect(locks).toHaveLength(1)
    expect(locks[0].authoritySnapshotId).toBe('snap-1')
    expect(locks[0].policyVersion).toBe('2026.06')
    expect(locks[0].boundaryHash).toBe('bh')
  })

  test('fail-closed on malformed context', async () => {
    // @ts-expect-error intentionally malformed
    expect((await engine.evaluate(null)).passed).toBe(false)
  })
})

describe('Layer 2 — AuditLockService', () => {
  test('records what/who/why/when plus provenance', () => {
    const svc = new AuditLockService()
    const rec = svc.lock('chunk-1', 'tenant-A', 'hold', { policyVersion: 'p1' })
    expect(rec.documentId).toBe('chunk-1')
    expect(rec.tenantId).toBe('tenant-A')
    expect(rec.reason).toBe('hold')
    expect(rec.lockedAt).toBeTruthy()
    expect(rec.policyVersion).toBe('p1')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 3 — DAR
// ─────────────────────────────────────────────────────────────────────────────

describe('Layer 3 — DAREngine', () => {
  function build() {
    const assignments = new InMemoryAssignmentResolver()
    const topics = new InMemoryTopicPolicyProvider()
    topics.set({
      policyId: 'pol-1', tenantId: 'tenant-A', role: 'manager',
      allowedTopics: ['maintenance', 'billing'], version: '2026.06', active: true,
    })
    const dar = new DAREngine(assignments, topics, { policyVersion: 'fallback' })
    return { assignments, topics, dar }
  }

  test('no assignment ⇒ empty boundary (fail-closed)', async () => {
    const { dar } = build()
    const b = await dar.resolve(mockClaim)
    expect(b.empty).toBe(true)
    expect(b.scopes).toHaveLength(0)
    expect(b.eligibleTopics).toHaveLength(0)
  })

  test('assignment ⇒ scopes + eligible topics from policy', async () => {
    const { assignments, dar } = build()
    assignments.grant(mockAssignment())
    const b = await dar.resolve(mockClaim)
    expect(b.empty).toBe(false)
    expect(b.scopes).toEqual([{ familyId: 'family-X', childId: null }])
    expect(b.eligibleTopics).toEqual(['billing', 'maintenance'])
    expect(b.allowedStatuses).toEqual(['ACTIVE'])
    expect(b.roleLevel).toBe(3)
    expect(b.policyVersion).toBe('2026.06')
  })

  test('multiple assignments union their scopes', async () => {
    const { assignments, dar } = build()
    assignments.grant(mockAssignment())
    assignments.grant(mockAssignment({
      assignmentId: 'asg-002', familyId: 'family-Y', childId: 'child-3',
    }))
    const b = await dar.resolve(mockClaim)
    expect(b.scopes).toHaveLength(2)
  })

  test('boundary is frozen (immutable)', async () => {
    const { assignments, dar } = build()
    assignments.grant(mockAssignment())
    const b = await dar.resolve(mockClaim)
    expect(Object.isFrozen(b)).toBe(true)
    expect(Object.isFrozen(b.scopes)).toBe(true)
  })

  test('revoked assignment is ignored', async () => {
    const { assignments, dar } = build()
    assignments.grant(mockAssignment())
    assignments.revoke('user-001', 'tenant-A')
    const b = await dar.resolve(mockClaim)
    expect(b.empty).toBe(true)
  })

  test('authoritySnapshotId is deterministic for same assignment set', async () => {
    const a = build(); a.assignments.grant(mockAssignment())
    const b = build(); b.assignments.grant(mockAssignment())
    const r1 = await a.dar.resolve(mockClaim)
    const r2 = await b.dar.resolve(mockClaim)
    expect(r1.authoritySnapshotId).toBe(r2.authoritySnapshotId)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 4 — APPROVED EVIDENCE CORPUS
// ─────────────────────────────────────────────────────────────────────────────

describe('Layer 4 — ApprovedEvidenceCorpus', () => {
  const corpus = new ApprovedEvidenceCorpus()
  const boundary = mockBoundary()

  test('keeps a fully eligible chunk', () => {
    const r = corpus.filter([mockChunk()], boundary)
    expect(r.chunks).toHaveLength(1)
    expect(r.filteredCount).toBe(0)
  })

  test('drops cross-tenant chunk', () => {
    const r = corpus.filter([mockChunk({ tenantId: 'tenant-B' })], boundary)
    expect(r.chunks).toHaveLength(0)
    expect(r.removed[0].reason).toBe('tenant-mismatch')
  })

  test('drops out-of-scope chunk', () => {
    const r = corpus.filter([mockChunk({ familyId: 'family-Y' })], boundary)
    expect(r.removed[0].reason).toBe('scope-mismatch')
  })

  test('drops ineligible-topic chunk', () => {
    const r = corpus.filter([mockChunk({ topicKey: 'legal' })], boundary)
    expect(r.removed[0].reason).toBe('topic-not-eligible')
  })

  test('drops non-ACTIVE chunk', () => {
    const r = corpus.filter([mockChunk({ status: 'REVOKED' })], boundary)
    expect(r.removed[0].reason).toBe('status-not-allowed')
  })

  test('drops legal-hold chunk', () => {
    const r = corpus.filter([mockChunk({ legalHold: true })], boundary)
    expect(r.removed[0].reason).toBe('legal-hold')
  })

  test('drops not-yet-effective chunk', () => {
    const r = corpus.filter([mockChunk({ validFrom: FUTURE })], boundary)
    expect(r.removed[0].reason).toBe('not-yet-effective')
  })

  test('drops retention-expired chunk', () => {
    const r = corpus.filter([mockChunk({ validTo: PAST })], boundary)
    expect(r.removed[0].reason).toBe('retention-expired')
  })

  test('empty boundary drops everything (no-authority)', () => {
    const r = corpus.filter([mockChunk()], mockBoundary({ empty: true, scopes: [] }))
    expect(r.chunks).toHaveLength(0)
    expect(r.removed[0].reason).toBe('no-authority')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 5 — EVIDENCE LEDGER
// ─────────────────────────────────────────────────────────────────────────────

const baseCommit = {
  claim:        mockClaim,
  requestId:    'req-1',
  decision:     'ALLOW' as const,
  darDecisionHash: 'dar-hash',
  retrievedEvidenceIds: ['chunk-001'],
  promptText:   'What is the maintenance policy?',
  responseText: 'AI response text',
  modelUsed:    'claude-sonnet-4-6',
  tokenCount:   512,
  authoritySnapshotId: 'snap-1',
  policyVersion:       '2026.06',
  boundaryHash:        'dar-hash',
}

describe('Layer 5 — BlockBuilder', () => {
  const builder = new BlockBuilder()

  test('builds a genesis block with previousHash GENESIS', () => {
    const b = builder.build({ ...baseCommit, prevBlock: null, blockNumber: 1 })
    expect(b.auditTrail.previousHash).toBe('GENESIS')
    expect(b.decision).toBe('ALLOW')
    expect(b.promptHash).not.toBe('What is the maintenance policy?')
    expect(b.responseHash).toBeTruthy()
  })

  test('never stores raw prompt/response — only hashes', () => {
    const b = builder.build({ ...baseCommit, prevBlock: null, blockNumber: 1 })
    expect(JSON.stringify(b)).not.toContain('AI response text')
  })

  test('checksum recomputes deterministically (canonical JSON)', () => {
    const b = builder.build({ ...baseCommit, prevBlock: null, blockNumber: 1 })
    const verifier = new ChainVerifier(new InMemoryLedgerStore())
    expect(verifier.recomputeChecksum(b)).toBe(b.auditTrail.currentHash)
  })

  test('authority provenance is bound into the block', () => {
    const b = builder.build({ ...baseCommit, prevBlock: null, blockNumber: 1 })
    expect(b.authority?.authoritySnapshotId).toBe('snap-1')
    expect(b.authority?.policyVersion).toBe('2026.06')
  })
})

describe('Layer 5 — EvidenceLedger', () => {
  let store: InMemoryLedgerStore
  let ledger: EvidenceLedger
  beforeEach(() => {
    store = new InMemoryLedgerStore()
    ledger = new EvidenceLedger(store)
  })

  test('commits a chain and links blocks', async () => {
    const b1 = await ledger.commit(baseCommit)
    const b2 = await ledger.commit(baseCommit)
    expect(b1.blockNumber).toBe(1)
    expect(b2.blockNumber).toBe(2)
    expect(b2.auditTrail.previousHash).toBe(b1.auditTrail.currentHash)
  })

  test('verifies an intact chain', async () => {
    await ledger.commit(baseCommit)
    await ledger.commit(baseCommit)
    const r = await ledger.verifyChain('tenant-A', 1, 2)
    expect(r.valid).toBe(true)
    expect(r.totalBlocks).toBe(2)
  })

  test('detects tampering (checksum mismatch)', async () => {
    await ledger.commit(baseCommit)
    await ledger.commit(baseCommit)
    store.tamperBlock('tenant-A', 1, b => { b.decision = 'DENY' })
    const r = await ledger.verifyChain('tenant-A', 1, 2)
    expect(r.valid).toBe(false)
    expect(r.brokenAt).toBe(1)
  })

  test('verifyFromGenesis proves chain from block 1', async () => {
    const g = await ledger.commit(baseCommit)
    await ledger.commit(baseCommit)
    const ok = await ledger.verifyFromGenesis('tenant-A')
    expect(ok.valid).toBe(true)
    const pinned = await ledger.verifyFromGenesis('tenant-A', g.auditTrail.currentHash)
    expect(pinned.valid).toBe(true)
    const bad = await ledger.verifyFromGenesis('tenant-A', 'wrong')
    expect(bad.valid).toBe(false)
  })

  test('replay surfaces decision + authority provenance', async () => {
    await ledger.commit(baseCommit)
    const r = await ledger.replayBlock('tenant-A', 1)
    expect(r.decision).toBe('ALLOW')
    expect(r.chainIntegrity).toBe('valid')
    expect(r.authority?.authoritySnapshotId).toBe('snap-1')
    expect(r.authority?.policyVersion).toBe('2026.06')
  })

  test('concurrent commits do not fork the chain', async () => {
    await Promise.all(Array.from({ length: 10 }, () => ledger.commit(baseCommit)))
    const r = await ledger.verifyChain('tenant-A', 1, 10)
    expect(r.valid).toBe(true)
    expect(r.totalBlocks).toBe(10)
  })
})
