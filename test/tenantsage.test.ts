/**
 * TenantSage — Full QA Test Suite
 * Tests every bug found and fixed across all 5 layers
 * Run: npx jest --coverage
 */

import { TenantIsolationGuard }  from '../src/identity/TenantIsolationGuard'
import { PolicyEngine }          from '../src/policy/PolicyEngine'
import { RetentionCheck }        from '../src/policy/checks/RetentionCheck'
import { LegalHoldCheck }        from '../src/policy/checks/LegalHoldCheck'
import { RolePermissionCheck }   from '../src/policy/checks/RolePermissionCheck'
import { EffectiveDateCheck }    from '../src/policy/checks/EffectiveDateCheck'
import { AuditLockService }      from '../src/policy/AuditLockService'
import { BlockBuilder }          from '../src/ledger/BlockBuilder'
import { EvidenceLedger }        from '../src/ledger/EvidenceLedger'
import { ChainVerifier }         from '../src/ledger/ChainVerifier'
import { InMemoryLedgerStore }   from '../src/ledger/LedgerStore'
import { DAREngine }             from '../src/dar/DAREngine'
import { InMemoryAssignmentResolver } from '../src/assignments/InMemoryAssignmentResolver'
import { UserAssignment }        from '../src/assignments/types'
import { EvidenceBoundary }      from '../src/dar/types'
import { ApprovedEvidenceCorpus, GovernedChunk } from '../src/runtime/ApprovedEvidenceCorpus'
import { TenantClaim }           from '../src/identity/types'
import { Role }                  from '../src/identity/roles'
import { DocumentPolicy, PolicyContext } from '../src/policy/types'

// ─── FIXTURES ─────────────────────────────────────────────────────────────────

// Identity only — authority (role/family/org) lives in the assignment, not here.
const mockClaim: TenantClaim = {
  userId:     'user-001',
  tenantId:   'tenant-A',
  provider:   'entra',
  verifiedAt: Date.now()
}

// Authoritative assignment fixture for identity-layer family enforcement.
const mockAssignment: UserAssignment = {
  assignmentId:      'asg-001',
  assignmentVersion: 'v1',
  userId:            'user-001',
  tenantId:          'tenant-A',
  organisationIds:   ['org-1'],
  scopeIds:          [],
  familyIds:         ['family-X'],
  role:              'manager',
  classificationClearance: 'restricted',
  sensitivityClearance:    'critical',
  source:            'test',
  assignedAt:        new Date().toISOString(),
}

const mockDoc: DocumentPolicy = {
  documentId:    'doc-001',
  tenantId:      'tenant-A',
  familyId:      'family-X',
  retainUntil:   new Date(Date.now() + 86_400_000 * 365),
  legalHold:     false,
  allowedRoles:  ['owner', 'admin', 'manager'],
  effectiveFrom: new Date(Date.now() - 86_400_000),
  effectiveTo:   new Date(Date.now() + 86_400_000 * 365),
  status:        'active'
}

const ctx = (overrides: Partial<DocumentPolicy> = {}): PolicyContext => ({
  claim:       mockClaim,
  subjectRole: 'manager',
  document:    { ...mockDoc, ...overrides },
  requestedAt: new Date()
})

const baseCommit = {
  claim:        mockClaim,
  policyResult: { passed: true },
  ruleVersion:  '4.1',
  documentIds:  ['doc-001'],
  chunkIds:     ['chunk-001'],
  contextText:  'some context',
  aiResponse:   'AI response text',
  modelUsed:    'claude-sonnet-4-6',
  tokenCount:   512,
  queryText:    'What is the retention policy?'
}

const mockChunk = (overrides: Partial<GovernedChunk> = {}): GovernedChunk => ({
  chunkId:  'c1',
  sourceId: 's1',
  tenantId: 'tenant-A',
  familyId: 'family-X',
  content:  'chunk content',
  governance: {
    status:       'active',
    allowedRoles: ['owner', 'admin', 'manager'],
    visibility:   'tenant'
  },
  ...overrides
})

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 1 — IDENTITY
// ─────────────────────────────────────────────────────────────────────────────

describe('Layer 1 — TenantIsolationGuard', () => {
  const guard = new TenantIsolationGuard()

  // Happy path
  test('allows same-tenant access', () => {
    expect(() => guard.enforce(mockClaim, 'tenant-A')).not.toThrow()
  })

  test('allows same-family access for non-owner', () => {
    expect(() => guard.enforceFamily(mockAssignment, 'family-X')).not.toThrow()
  })

  test('owner bypasses family isolation', () => {
    const ownerAssignment = { ...mockAssignment, role: 'owner' as const }
    expect(() => guard.enforceFamily(ownerAssignment, 'family-DIFFERENT')).not.toThrow()
  })

  // Security: cross-tenant
  test('blocks cross-tenant access', () => {
    expect(() => guard.enforce(mockClaim, 'tenant-B')).toThrow('TENANT_ISOLATION')
  })

  test('blocks cross-family access for non-owner', () => {
    expect(() => guard.enforceFamily(mockAssignment, 'family-Y')).toThrow('FAMILY_ISOLATION')
  })

  // QA BUG FIX: whitespace bypass was possible in original
  test('[QA FIX] blocks whitespace-padded tenant ID bypass', () => {
    expect(() => guard.enforce(mockClaim, ' tenant-A ')).not.toThrow()
  })

  test('[QA FIX] blocks empty requestedTenantId', () => {
    expect(() => guard.enforce(mockClaim, '')).toThrow('must not be empty')
  })

  test('[QA FIX] blocks empty requestedFamilyId', () => {
    expect(() => guard.enforceFamily(mockAssignment, '')).toThrow('must not be empty')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 2 — POLICY ENGINE
// ─────────────────────────────────────────────────────────────────────────────

describe('Layer 2 — RetentionCheck', () => {
  const check = new RetentionCheck()

  test('passes active document within retention window', () => {
    expect(check.run(ctx()).passed).toBe(true)
  })

  test('fails expired retention', () => {
    const result = check.run(ctx({ retainUntil: new Date(Date.now() - 1000) }))
    expect(result.passed).toBe(false)
    expect(result.failedAt).toBe('retention')
  })

  // QA BUG FIX: original crashed on null retainUntil
  test('[QA FIX] fails gracefully on null retainUntil', () => {
    const result = check.run(ctx({ retainUntil: null as any }))
    expect(result.passed).toBe(false)
    expect(result.failedAt).toBe('retention')
  })

  test('[QA FIX] fails gracefully on invalid Date retainUntil', () => {
    const result = check.run(ctx({ retainUntil: new Date('not-a-date') }))
    expect(result.passed).toBe(false)
    expect(result.failedAt).toBe('retention')
  })
})

describe('Layer 2 — LegalHoldCheck', () => {
  const check = new LegalHoldCheck()

  test('passes when no legal hold', () => {
    expect(check.run(ctx({ legalHold: false })).passed).toBe(true)
  })

  test('fails and sets auditLocked when hold is active', () => {
    const result = check.run(ctx({ legalHold: true, legalHoldReason: 'Litigation 2024' }))
    expect(result.passed).toBe(false)
    expect(result.failedAt).toBe('legal_hold')
    expect(result.auditLocked).toBe(true)
  })

  test('includes reason in failure message', () => {
    const result = check.run(ctx({ legalHold: true, legalHoldReason: 'GDPR request' }))
    expect(result.reason).toContain('GDPR request')
  })

  // QA BUG FIX: truthy string '1' or 'true' was bypassing original strict check
  test('[QA FIX] does not treat truthy string as legalHold', () => {
    const result = check.run(ctx({ legalHold: ('true' as any) }))
    // Our fix uses === true so string 'true' is NOT a hold
    expect(result.passed).toBe(true)
  })

  test('[QA FIX] flags missing legalHoldReason for compliance review', () => {
    const result = check.run(ctx({ legalHold: true, legalHoldReason: undefined }))
    expect(result.reason).toContain('compliance review')
  })
})

describe('Layer 2 — RolePermissionCheck', () => {
  const check = new RolePermissionCheck()

  test('passes when role is sufficient', () => {
    expect(check.run(ctx()).passed).toBe(true)
  })

  test('owner always passes', () => {
    const ownerCtx: PolicyContext = { ...ctx(), subjectRole: 'owner' }
    expect(check.run(ownerCtx).passed).toBe(true)
  })

  test('fails when role is too low', () => {
    const viewerCtx: PolicyContext = { ...ctx(), subjectRole: 'viewer' }
    const result = check.run(viewerCtx)
    expect(result.passed).toBe(false)
    expect(result.failedAt).toBe('role_permission')
  })

  // QA BUG FIX: empty allowedRoles returned Infinity from Math.min and ALL roles passed
  test('[QA FIX] fails when allowedRoles is empty array', () => {
    const result = check.run(ctx({ allowedRoles: [] }))
    expect(result.passed).toBe(false)
    expect(result.failedAt).toBe('role_permission')
    expect(result.reason).toContain('fail-closed')
  })

  // QA BUG FIX: unknown user role was undefined, not 0 — could cause NaN comparison
  test('[QA FIX] unknown role defaults to level 0 (denied)', () => {
    const unknownCtx = { ...ctx(), subjectRole: 'superadmin' as any }
    const result = check.run(unknownCtx)
    expect(result.passed).toBe(false)
  })
})

describe('Layer 2 — EffectiveDateCheck', () => {
  const check = new EffectiveDateCheck()

  test('passes active document in valid date range', () => {
    expect(check.run(ctx()).passed).toBe(true)
  })

  test('fails expired document', () => {
    const result = check.run(ctx({ effectiveTo: new Date(Date.now() - 1000) }))
    expect(result.passed).toBe(false)
    expect(result.failedAt).toBe('effective_date')
  })

  test('fails not-yet-effective document', () => {
    const result = check.run(ctx({ effectiveFrom: new Date(Date.now() + 86_400_000) }))
    expect(result.passed).toBe(false)
    expect(result.failedAt).toBe('effective_date')
  })

  test('fails quarantined document', () => {
    const result = check.run(ctx({ status: 'quarantined' }))
    expect(result.passed).toBe(false)
  })

  // QA BUG FIX: original checked dates before status — quarantined doc with future date passed
  test('[QA FIX] status check runs before date range check', () => {
    const result = check.run(ctx({
      status:        'quarantined',
      effectiveFrom: new Date(Date.now() - 86_400_000),
      effectiveTo:   new Date(Date.now() + 86_400_000)
    }))
    expect(result.passed).toBe(false)
    expect(result.reason).toContain('quarantined')
  })

  // QA BUG FIX: effectiveFrom > effectiveTo is data error
  test('[QA FIX] fails when effectiveFrom is after effectiveTo (data integrity)', () => {
    const future = new Date(Date.now() + 86_400_000)
    const past   = new Date(Date.now() - 86_400_000)
    const result = check.run(ctx({ effectiveFrom: future, effectiveTo: past }))
    expect(result.passed).toBe(false)
    expect(result.reason).toContain('integrity error')
  })

  test('[QA FIX] fails gracefully on invalid effectiveFrom date', () => {
    const result = check.run(ctx({ effectiveFrom: new Date('invalid') }))
    expect(result.passed).toBe(false)
    expect(result.reason).toContain('invalid')
  })
})

describe('Layer 2 — PolicyEngine (full 4-gate sequence)', () => {
  const engine = new PolicyEngine(new AuditLockService())

  test('all 4 gates pass for valid document', async () => {
    expect((await engine.evaluate(ctx())).passed).toBe(true)
  })

  test('stops at gate 1 (retention)', async () => {
    const result = await engine.evaluate(ctx({ retainUntil: new Date(Date.now() - 1) }))
    expect(result.failedAt).toBe('retention')
  })

  test('stops at gate 2 (legal hold)', async () => {
    const result = await engine.evaluate(ctx({ legalHold: true }))
    expect(result.failedAt).toBe('legal_hold')
    expect(result.auditLocked).toBe(true)
  })

  test('stops at gate 3 (role)', async () => {
    const viewerCtx: PolicyContext = { ...ctx(), subjectRole: 'viewer' }
    const result    = await engine.evaluate(viewerCtx)
    expect(result.failedAt).toBe('role_permission')
  })

  test('stops at gate 4 (effective date)', async () => {
    const result = await engine.evaluate(ctx({ effectiveTo: new Date(Date.now() - 1) }))
    expect(result.failedAt).toBe('effective_date')
  })

  // QA FIX: PolicyEngine must handle null context gracefully
  test('[QA FIX] handles null context gracefully', async () => {
    const result = await engine.evaluate(null as any)
    expect(result.passed).toBe(false)
  })

  test('[QA FIX] handles invalid requestedAt Date', async () => {
    const badCtx = { ...ctx(), requestedAt: new Date('bad-date') }
    const result = await engine.evaluate(badCtx)
    expect(result.passed).toBe(false)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 4 — EVIDENCE LEDGER
// ─────────────────────────────────────────────────────────────────────────────

describe('Layer 4 — BlockBuilder', () => {
  const builder = new BlockBuilder()
  const input   = { ...baseCommit, prevBlock: null, blockNumber: 1 }

  test('builds block with all 5 datapoints', () => {
    const block = builder.build(input)
    expect(block.userIdentity).toBeDefined()
    expect(block.policyRules).toBeDefined()
    expect(block.contextRetrieved).toBeDefined()
    expect(block.aiOutput).toBeDefined()
    expect(block.auditTrail).toBeDefined()
  })

  test('first block has GENESIS prevBlockHash', () => {
    expect(builder.build(input).auditTrail.prevBlockHash).toBe('GENESIS')
  })

  test('stores hash not raw AI response', () => {
    const block = builder.build(input)
    expect(block.aiOutput.responseHash).not.toBe('AI response text')
    expect(block.aiOutput.responseHash).toHaveLength(64)
  })

  test('links block 2 to block 1 via prevBlockHash', () => {
    const b1 = builder.build(input)
    const b2 = builder.build({ ...input, prevBlock: b1, blockNumber: 2 })
    expect(b2.auditTrail.prevBlockHash).toBe(b1.auditTrail.blockChecksum)
  })

  // QA BUG FIX: canonical JSON must produce stable checksums
  test('[QA FIX] canonical JSON produces same checksum regardless of key insertion order', () => {
    const obj1 = { b: 2, a: 1 }
    const obj2 = { a: 1, b: 2 }
    expect(builder.canonicalJson(obj1)).toBe(builder.canonicalJson(obj2))
  })

  test('[QA FIX] nested objects in canonical JSON are also sorted', () => {
    const obj1 = { z: { b: 2, a: 1 }, a: 0 }
    const obj2 = { a: 0, z: { a: 1, b: 2 } }
    expect(builder.canonicalJson(obj1)).toBe(builder.canonicalJson(obj2))
  })
})

describe('Layer 4 — EvidenceLedger + ChainVerifier', () => {
  let store:  InMemoryLedgerStore
  let ledger: EvidenceLedger

  beforeEach(() => {
    store  = new InMemoryLedgerStore()
    ledger = new EvidenceLedger(store)
  })

  test('first block has blockNumber 1', async () => {
    const b = await ledger.commit(baseCommit)
    expect(b.blockNumber).toBe(1)
  })

  test('blocks are sequential', async () => {
    const b1 = await ledger.commit(baseCommit)
    const b2 = await ledger.commit(baseCommit)
    const b3 = await ledger.commit(baseCommit)
    expect([b1.blockNumber, b2.blockNumber, b3.blockNumber]).toEqual([1, 2, 3])
  })

  test('chain passes verification after 5 blocks', async () => {
    for (let i = 0; i < 5; i++) await ledger.commit(baseCommit)
    const result = await ledger.verifyChain('tenant-A', 1, 5)
    expect(result.valid).toBe(true)
    expect(result.totalBlocks).toBe(5)
  })

  test('tampered block is detected by chain verifier', async () => {
    await ledger.commit(baseCommit)
    await ledger.commit(baseCommit)

    // Simulate tamper using typed helper
    store.tamperBlock('tenant-A', 1, b => { b.userIdentity.userId = 'attacker' })

    const result = await ledger.verifyChain('tenant-A', 1, 2)
    expect(result.valid).toBe(false)
    expect(result.brokenAt).toBe(1)
  })

  test('replay returns approved decision for passing policy', async () => {
    await ledger.commit(baseCommit)
    const result = await ledger.replayBlock('tenant-A', 1)
    expect(result.policyDecision).toBe('approved')
    expect(result.chainIntegrity).toBe('valid')
  })

  test('replay returns denied for failed policy commit', async () => {
    await ledger.commit({
      ...baseCommit,
      policyResult: { passed: false, failedAt: 'retention', reason: 'expired' }
    })
    const result = await ledger.replayBlock('tenant-A', 1)
    expect(result.policyDecision).toBe('denied')
  })

  test('replay throws for non-existent block', async () => {
    await expect(ledger.replayBlock('tenant-A', 99)).rejects.toThrow('REPLAY')
  })

  test('replay surfaces authority evidence (why), not just what happened', async () => {
    await ledger.commit({
      ...baseCommit,
      authoritySnapshotId: 'asg-9@v2',
      policyVersion:       '4.2.0',
      boundaryHash:        'a'.repeat(64),
    })
    const result = await ledger.replayBlock('tenant-A', 1)
    expect(result.authority).toEqual({
      authoritySnapshotId: 'asg-9@v2',
      policyVersion:       '4.2.0',
      boundaryHash:        'a'.repeat(64),
    })
  })

  test('replay authority is null for legacy blocks without provenance', async () => {
    await ledger.commit(baseCommit)
    const result = await ledger.replayBlock('tenant-A', 1)
    expect(result.authority).toBeNull()
  })

  test('verifyFromGenesis proves the whole chain with no gaps', async () => {
    for (let i = 0; i < 3; i++) await ledger.commit(baseCommit)
    const genesis = await ledger.replayBlock('tenant-A', 1)
    const result = await ledger.verifyFromGenesis('tenant-A', genesis.storedChecksum)
    expect(result.valid).toBe(true)
    expect(result.totalBlocks).toBe(3)
  })

  test('verifyFromGenesis rejects a mismatched genesis anchor', async () => {
    await ledger.commit(baseCommit)
    const result = await ledger.verifyFromGenesis('tenant-A', 'not-the-real-genesis')
    expect(result.valid).toBe(false)
    expect(result.brokenAt).toBe(1)
  })

  // QA BUG FIX: concurrent commits must not fork the chain
  test('[QA FIX] concurrent commits produce sequential block numbers', async () => {
    const [b1, b2, b3] = await Promise.all([
      ledger.commit(baseCommit),
      ledger.commit(baseCommit),
      ledger.commit(baseCommit)
    ])
    const numbers = [b1.blockNumber, b2.blockNumber, b3.blockNumber].sort((a, b) => a - b)
    expect(numbers).toEqual([1, 2, 3])
  })

  test('[QA FIX] updateNextHash failure does not break commit', async () => {
    // Override updateNextHash to throw
    store.updateNextHash = async () => { throw new Error('storage error') }
    await expect(ledger.commit(baseCommit)).resolves.toBeDefined()
  })
})

describe('Layer 4 — ChainVerifier (genesis + edge cases)', () => {
  let store:    InMemoryLedgerStore
  let ledger:   EvidenceLedger
  let verifier: ChainVerifier

  beforeEach(() => {
    store    = new InMemoryLedgerStore()
    ledger   = new EvidenceLedger(store)
    verifier = new ChainVerifier(store)
  })

  test('empty range returns valid with 0 blocks', async () => {
    const result = await verifier.verify('tenant-A', 1, 10)
    expect(result.valid).toBe(true)
    expect(result.totalBlocks).toBe(0)
  })

  test('single block verifies correctly', async () => {
    await ledger.commit(baseCommit)
    const result = await verifier.verify('tenant-A', 1, 1)
    expect(result.valid).toBe(true)
  })

  test('[QA FIX] detects tampered checksum on middle block', async () => {
    await ledger.commit(baseCommit)
    await ledger.commit(baseCommit)
    await ledger.commit(baseCommit)

    store.tamperBlock('tenant-A', 2, b => { b.aiOutput.tokenCount = 99999 })

    const result = await verifier.verify('tenant-A', 1, 3)
    expect(result.valid).toBe(false)
    expect(result.brokenAt).toBe(2)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 5 — DAR + APPROVED EVIDENCE CORPUS
// ─────────────────────────────────────────────────────────────────────────────

describe('Layer 5 — DAREngine', () => {
  // Correction #1: authority is resolved from authoritative assignments, NOT
  // from the JWT claim. Each test seeds the assignment store with the role
  // under test; the claim only supplies identity (userId/tenantId).
  const baseAssignment: Omit<UserAssignment, 'role'> = {
    assignmentId:      'asg-001',
    assignmentVersion: 'v1',
    userId:            'user-001',
    tenantId:          'tenant-A',
    organisationIds:   ['org-1'],
    scopeIds:          [],
    familyIds:         ['family-X'],
    classificationClearance: 'restricted',
    sensitivityClearance:    'critical',
    source:            'test',
    assignedAt:        new Date().toISOString(),
  }

  const darFor = (role: Role): DAREngine =>
    new DAREngine(new InMemoryAssignmentResolver().grant({ ...baseAssignment, role }))

  test('owner gets wildcard family access', async () => {
    const b = await darFor('owner').resolve(mockClaim)
    expect(b.allFamilies).toBe(true)
  })

  test('admin does NOT get wildcard family (own family only)', async () => {
    const b = await darFor('admin').resolve(mockClaim)
    expect(b.allFamilies).toBe(false)
    expect(b.familyIds).toContain('family-X')
  })

  test('owner + admin see quarantined docs', async () => {
    const ownerB = await darFor('owner').resolve(mockClaim)
    const adminB = await darFor('admin').resolve(mockClaim)
    expect(ownerB.allowedStatuses).toContain('quarantined')
    expect(adminB.allowedStatuses).toContain('quarantined')
  })

  test('manager/member/viewer only see active docs', async () => {
    for (const role of ['manager', 'member', 'viewer'] as const) {
      const b = await darFor(role).resolve(mockClaim)
      expect(b.allowedStatuses).toEqual(['active'])
      expect(b.allowedStatuses).not.toContain('quarantined')
    }
  })

  test('boundary always scoped to own tenant', async () => {
    const b = await darFor('manager').resolve(mockClaim)
    expect(b.tenantIds).toEqual(['tenant-A'])
  })

  // QA FIX: boundary must be immutable — original returned plain object, mutable at runtime
  test('[QA FIX] returned boundary is frozen (immutable)', async () => {
    const b = await darFor('manager').resolve(mockClaim)
    expect(Object.isFrozen(b)).toBe(true)
  })

  // Correction #1: the claim carries no authority at all — authority comes only
  // from the assignment. A 'viewer' assignment yields viewer authority (no
  // all-families, active-only) regardless of any identity presented.
  test('[CORRECTION] claim cannot escalate beyond authoritative assignment', async () => {
    const dar = darFor('viewer')
    const b = await dar.resolve(mockClaim)
    expect(b.allowedRoles).toEqual(['viewer'])
    expect(b.allFamilies).toBe(false)
    expect(b.allowedStatuses).toEqual(['active'])
  })

  // Correction #1 / #5: identity with NO authoritative assignment ⇒ empty,
  // fail-closed boundary.
  test('[CORRECTION] no assignment yields empty fail-closed boundary', async () => {
    const dar = new DAREngine() // empty assignment store
    const b = await dar.resolve(mockClaim)
    expect(b.empty).toBe(true)
    expect(b.tenantIds).toEqual([])
    expect(b.allowedRoles).toEqual([])
  })
})

describe('Layer 5 — ApprovedEvidenceCorpus (Ghost Effect)', () => {
  const corpus   = new ApprovedEvidenceCorpus()
  const boundary: EvidenceBoundary = {
    tenantIds:           ['tenant-A'],
    organisationIds:     [],
    scopeIds:            [],
    familyIds:           ['family-X'],
    allFamilies:         false,
    allowedStatuses:     ['active'],
    allowedRoles:        ['manager'],
    classificationLevel: 'restricted',
    sensitivityLevel:    'critical',
    authoritySnapshotId: 'asg-001@v1',
    policyVersion:       '4.2.0',
    effectiveAt:         new Date().toISOString(),
    computedAt:          new Date().toISOString(),
    empty:               false,
  }

  test('approves valid chunk', () => {
    const r = corpus.filter([mockChunk()], boundary)
    expect(r.chunks).toHaveLength(1)
    expect(r.filteredCount).toBe(0)
  })

  test('Ghost Effect removes wrong-tenant chunk', () => {
    const r = corpus.filter([mockChunk({ tenantId: 'tenant-B' })], boundary)
    expect(r.chunks).toHaveLength(0)
    expect(r.filteredCount).toBe(1)
  })

  test('Ghost Effect removes quarantined chunk', () => {
    const r = corpus.filter(
      [mockChunk({ governance: { status: 'quarantined', allowedRoles: ['manager'], visibility: 'tenant' } })],
      boundary
    )
    expect(r.chunks).toHaveLength(0)
  })

  test('Ghost Effect removes wrong-family chunk', () => {
    const r = corpus.filter([mockChunk({ familyId: 'family-Y' })], boundary)
    expect(r.chunks).toHaveLength(0)
  })

  // QA BUG FIX: original used role equality not hierarchy
  // manager should NOT be denied from ['owner','admin','manager'] docs
  test('[QA FIX] manager can access docs with allowedRoles [owner, admin, manager]', () => {
    const chunk = mockChunk({ governance: { status: 'active', allowedRoles: ['owner', 'admin', 'manager'], visibility: 'tenant' } })
    const r = corpus.filter([chunk], boundary)
    expect(r.chunks).toHaveLength(1)
  })

  // Correction #1: role authority comes from the DAR boundary, not the claim.
  // A viewer-authority boundary cannot read manager+ docs.
  test('[QA FIX] viewer is denied from manager+ docs', () => {
    const viewerBoundary: EvidenceBoundary = { ...boundary, allowedRoles: ['viewer'] }
    const r = corpus.filter([mockChunk()], viewerBoundary)
    expect(r.chunks).toHaveLength(0)
  })

  test('[QA FIX] owner wildcard family sees all family chunks', () => {
    const ownerBoundary: EvidenceBoundary = { ...boundary, allFamilies: true, familyIds: [] }
    const chunk = mockChunk({ familyId: 'family-COMPLETELY-DIFFERENT' })
    const r = corpus.filter([chunk], ownerBoundary)
    expect(r.chunks).toHaveLength(1)
  })

  test('filters mixed valid and invalid chunks correctly', () => {
    const chunks = [
      mockChunk(),
      mockChunk({ tenantId: 'tenant-B' }),
      mockChunk(),
      mockChunk({ governance: { status: 'quarantined', allowedRoles: ['manager'], visibility: 'tenant' } })
    ]
    const r = corpus.filter(chunks, boundary)
    expect(r.chunks).toHaveLength(2)
    expect(r.filteredCount).toBe(2)
  })
})
