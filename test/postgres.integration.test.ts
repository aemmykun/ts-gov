import { Pool } from 'pg'
import {
  PgContext,
  applySchema,
  PostgresAssignmentResolver,
  PostgresTopicPolicyProvider,
  PostgresGovernancePolicyProvider,
  PostgresLedgerStore,
  PostgresLedgerLock,
  PostgresVectorIndex,
  PostgresAuditLockService,
  PostgresAuthorityStore,
  PostgresPolicyVersionStore,
  PostgresHandoffStore,
} from '../src/persistence'
import { DAREngine } from '../src/dar/DAREngine'
import { TrustRAGRetriever } from '../src/trustrag/TrustRAGRetriever'
import { EvidenceLedger } from '../src/ledger/EvidenceLedger'
import { PolicyEngine } from '../src/policy/PolicyEngine'
import { TenantClaim } from '../src/identity/types'

// Integration tests run only when DATABASE_URL points at a Postgres with the
// `vector` and `pgcrypto` extensions available (e.g. pgvector/pgvector:pg16).
// Without it the suite is skipped so the default `npm test` stays green.
const URL = process.env.DATABASE_URL
const APP_ROLE = 'tenantsage_app'

const TA = '11111111-1111-1111-1111-111111111111'
const TB = '22222222-2222-2222-2222-222222222222'
const FAM_A = 'aaaaaaaa-0000-0000-0000-000000000001'
const FAM_B = 'bbbbbbbb-0000-0000-0000-000000000001'
const USER1 = '99999999-0000-0000-0000-000000000001'
const RP_A = 'cccccccc-0000-0000-0000-000000000001'
const SRC_A = 'dddddddd-0000-0000-0000-000000000001'
const CH_ACTIVE = 'eeeeeeee-0000-0000-0000-000000000001'
const CH_REVOKED = 'eeeeeeee-0000-0000-0000-000000000002'
const CH_OFFTOPIC = 'eeeeeeee-0000-0000-0000-000000000003'
const CH_HELD = 'eeeeeeee-0000-0000-0000-000000000004'
const SRC_B = 'dddddddd-0000-0000-0000-000000000002'
const RP_B = 'cccccccc-0000-0000-0000-000000000002'
const CH_TENANT_B = 'eeeeeeee-0000-0000-0000-000000000005'

const claim = (): TenantClaim => ({
  userId: USER1,
  tenantId: TA,
  provider: 'entra',
  verifiedAt: Date.now(),
})

const run = URL ? describe : describe.skip

run('Postgres persistence (integration)', () => {
  let pool: Pool
  let pg: PgContext

  beforeAll(async () => {
    pool = new Pool({ connectionString: URL })

    // Fresh schema.
    await pool.query(`
      DROP TABLE IF EXISTS handoff_manifests, audit_locks, dar_decisions,
        authority_snapshots, policy_versions, evidence_ledger, rag_chunks,
        rag_sources, retention_policies, policies, user_assignments, children,
        users, families CASCADE;`)
    await applySchema(pool)

    // Least-privileged app role so RLS (FORCE) is actually enforced.
    await pool.query(`DROP OWNED BY ${APP_ROLE} CASCADE;`).catch(() => undefined)
    await pool.query(`DROP ROLE IF EXISTS ${APP_ROLE};`).catch(() => undefined)
    await pool.query(`CREATE ROLE ${APP_ROLE} NOLOGIN;`)
    await pool.query(`GRANT USAGE ON SCHEMA public TO ${APP_ROLE};`)
    await pool.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${APP_ROLE};`)

    // Seed as superuser (RLS bypassed) so cross-tenant fixtures can be created.
    await pool.query(`INSERT INTO users(id, external_subject, display_name) VALUES ($1,'sub-1','User One')`, [USER1])
    await pool.query(`INSERT INTO families(tenant_id, id, name) VALUES ($1,$2,'Fam A'),($3,$4,'Fam B')`, [TA, FAM_A, TB, FAM_B])
    await pool.query(
      `INSERT INTO user_assignments(tenant_id, user_id, family_id, child_id, role, ended_at)
       VALUES ($1,$2,$3,NULL,'staff',NULL),
              ($1,$2,$3,NULL,'staff', now()),            -- ended: must be ignored
              ($4,$2,$5,NULL,'admin',NULL)`,
      [TA, USER1, FAM_A, TB, FAM_B],
    )
    await pool.query(
      `INSERT INTO policies(tenant_id, role, allowed_topics, version, active)
       VALUES ($1,'staff', ARRAY['billing'], 'v1', true)`,
      [TA],
    )
    await pool.query(`INSERT INTO policy_versions(tenant_id, version, checksum) VALUES ($1,'v1','chk-v1')`, [TA])
    await pool.query(
      `INSERT INTO retention_policies(tenant_id, id, resource_type) VALUES ($1,$2,'document'),($3,$4,'document')`,
      [TA, RP_A, TB, RP_B],
    )
    await pool.query(
      `INSERT INTO rag_sources(tenant_id, id, family_id, child_id, source_type, source_uri,
         classification, retention_policy_id, legal_hold, valid_from)
       VALUES ($1,$2,$3,NULL,'doc','s3://a','internal',$4,false, now() - interval '1 day')`,
      [TA, SRC_A, FAM_A, RP_A],
    )
    await pool.query(
      `INSERT INTO rag_sources(tenant_id, id, family_id, child_id, source_type, source_uri,
         classification, retention_policy_id, legal_hold, valid_from)
       VALUES ($1,$2,$3,NULL,'doc','s3://b','internal',$4,false, now() - interval '1 day')`,
      [TB, SRC_B, FAM_B, RP_B],
    )
    const chunk = (id: string, tenant: string, family: string, source: string, topic: string, status: string, hold: boolean) =>
      pool.query(
        `INSERT INTO rag_chunks(tenant_id, id, source_id, family_id, child_id, topic_key,
           status, legal_hold, valid_from, chunk_text, embedding)
         VALUES ($1,$2,$3,$4,NULL,$5,$6,$7, now() - interval '1 day', $8, $9::vector)`,
        [tenant, id, source, family, topic, status, hold, `text-${id}`, '[0.1,0.2,0.3]'],
      )
    await chunk(CH_ACTIVE, TA, FAM_A, SRC_A, 'billing', 'ACTIVE', false)
    await chunk(CH_REVOKED, TA, FAM_A, SRC_A, 'billing', 'REVOKED', false)
    await chunk(CH_OFFTOPIC, TA, FAM_A, SRC_A, 'secret', 'ACTIVE', false)
    await chunk(CH_HELD, TA, FAM_A, SRC_A, 'billing', 'ACTIVE', true)
    await chunk(CH_TENANT_B, TB, FAM_B, SRC_B, 'billing', 'ACTIVE', false)

    pg = new PgContext({ pool, appRole: APP_ROLE })
  })

  afterAll(async () => {
    if (pool) await pool.end()
  })

  test('AssignmentResolver returns only active, in-tenant assignments', async () => {
    const resolver = new PostgresAssignmentResolver(pg)
    const amts = await resolver.resolve(USER1, TA)
    expect(amts).toHaveLength(1)
    expect(amts[0]).toMatchObject({ tenantId: TA, familyId: FAM_A, childId: null, role: 'staff' })
    expect(await resolver.resolve(USER1, TB)).toHaveLength(1) // the admin grant in B
  })

  test('TopicPolicyProvider returns the active policy', async () => {
    const provider = new PostgresTopicPolicyProvider(pg)
    const policy = await provider.getPolicy(TA, 'staff')
    expect(policy?.allowedTopics).toEqual(['billing'])
    expect(await provider.getPolicy(TA, 'manager')).toBeNull()
  })

  test('GovernancePolicyProvider binds source governance with policy version', async () => {
    const provider = new PostgresGovernancePolicyProvider(pg)
    const gov = await provider.getPolicy(SRC_A, TA)
    expect(gov).toMatchObject({ sourceId: SRC_A, tenantId: TA, classification: 'internal', policyVersion: 'v1' })
  })

  test('DAR + pgvector retrieval returns only the eligible chunk', async () => {
    const dar = new DAREngine(new PostgresAssignmentResolver(pg), new PostgresTopicPolicyProvider(pg))
    const boundary = await dar.resolve(claim())
    expect(boundary.empty).toBe(false)
    expect(boundary.eligibleTopics).toEqual(['billing'])

    const retriever = new TrustRAGRetriever(new PostgresVectorIndex(pg))
    const result = await retriever.searchRagChunksAudited([0.1, 0.2, 0.3], 10, boundary)
    expect(result.chunks.map(c => c.chunkId)).toEqual([CH_ACTIVE])
  })

  test('Ledger persists, reloads and verifies a hash chain across commits', async () => {
    const ledger = new EvidenceLedger(new PostgresLedgerStore(pg), new PostgresLedgerLock(pool))
    const b1 = await ledger.commit({
      claim: claim(), requestId: '00000000-0000-0000-0000-0000000000a1',
      decision: 'ALLOW', darDecisionHash: 'dar-1', retrievedEvidenceIds: [CH_ACTIVE],
      promptText: 'q', responseText: 'a',
      authoritySnapshotId: 'snap-1', policyVersion: 'v1', boundaryHash: 'bh-1',
    })
    const b2 = await ledger.commit({
      claim: claim(), requestId: '00000000-0000-0000-0000-0000000000a2',
      decision: 'DENY', darDecisionHash: 'dar-2', retrievedEvidenceIds: [],
      promptText: 'q2', responseText: '',
    })
    expect(b1.blockNumber).toBe(1)
    expect(b2.blockNumber).toBe(2)
    expect(b2.auditTrail.previousHash).toBe(b1.auditTrail.currentHash)

    const reloaded = await new PostgresLedgerStore(pg).getByNumber(TA, 1)
    expect(reloaded?.auditTrail.currentHash).toBe(b1.auditTrail.currentHash)
    expect(reloaded?.authority).toMatchObject({ authoritySnapshotId: 'snap-1', policyVersion: 'v1' })

    const verify = await ledger.verifyFromGenesis(TA)
    expect(verify.valid).toBe(true)
    const replay = await ledger.replayBlock(TA, 1)
    expect(replay.chainIntegrity).toBe('valid')
    expect(replay.recomputedChecksum).toBe(replay.storedChecksum)
  })

  test('Advisory commit lock serialises concurrent commits (no forked chain)', async () => {
    const ledger = new EvidenceLedger(new PostgresLedgerStore(pg), new PostgresLedgerLock(pool))
    const commits = Array.from({ length: 6 }, (_, i) =>
      ledger.commit({
        claim: claim(), requestId: `00000000-0000-0000-0000-0000000000b${i}`,
        decision: 'ALLOW', darDecisionHash: `c-${i}`, retrievedEvidenceIds: [],
        promptText: `p${i}`, responseText: `r${i}`,
      }),
    )
    const blocks = await Promise.all(commits)
    const numbers = blocks.map(b => b.blockNumber).sort((a, b) => a - b)
    expect(new Set(numbers).size).toBe(numbers.length) // no duplicate block numbers
    expect(await ledger.verifyFromGenesis(TA)).toMatchObject({ valid: true })
  })

  test('RLS isolates replay primitives across tenants', async () => {
    const store = new PostgresAuthorityStore(pg)
    await store.saveSnapshot({
      tenantId: TA, snapshotId: 'snap-A', userId: USER1,
      policyVersion: 'v1', boundaryHash: 'bh-A', boundaryJson: { scopes: [] },
    })
    await store.saveDecision({
      tenantId: TA, requestId: '00000000-0000-0000-0000-0000000000c1', userId: USER1,
      authoritySnapshotId: 'snap-A', boundaryHash: 'bh-A', policyVersion: 'v1', decision: 'ALLOW',
    })
    expect(await store.getSnapshot(TA, 'snap-A')).not.toBeNull()
    // Tenant B (same app role) cannot see tenant A's snapshot/decisions.
    expect(await store.getSnapshot(TB, 'snap-A')).toBeNull()
    expect(await store.listDecisions(TB)).toHaveLength(0)
  })

  test('PolicyVersionStore publishes and reads the latest version', async () => {
    const store = new PostgresPolicyVersionStore(pg)
    await store.publish({ tenantId: TA, version: 'v2', checksum: 'chk-v2' })
    expect(await store.getLatest(TA)).toMatchObject({ version: 'v2', checksum: 'chk-v2' })
  })

  test('AuditLockService persists a legal-hold lock with provenance via PolicyEngine', async () => {
    const audit = new PostgresAuditLockService(pg)
    const engine = new PolicyEngine(audit)
    const result = await engine.evaluate({
      claim: claim(),
      boundary: {
        tenantId: TA, scopes: [{ familyId: FAM_A, childId: null }],
        eligibleTopics: ['billing'], allowedStatuses: ['ACTIVE'], roleLevel: 1,
        authoritySnapshotId: 'snap-1', policyVersion: 'v1',
        effectiveAt: new Date().toISOString(), computedAt: new Date().toISOString(), empty: false,
      },
      resource: {
        resourceId: SRC_A, tenantId: TA, familyId: FAM_A, childId: null,
        topicKey: 'billing', status: 'ACTIVE', legalHold: true,
        validFrom: new Date(Date.now() - 86400000), validTo: null,
        policyVersion: 'v1',
      },
      requestedAt: new Date(),
      provenance: { authoritySnapshotId: 'snap-1', boundaryHash: 'bh-1' },
    })
    expect(result.passed).toBe(false)
    const locks = await audit.list(TA)
    expect(locks.length).toBeGreaterThanOrEqual(1)
    expect(locks[locks.length - 1]).toMatchObject({ tenantId: TA, policyVersion: 'v1', authoritySnapshotId: 'snap-1' })
  })

  test('HandoffStore persists an evidence-integrity manifest', async () => {
    const store = new PostgresHandoffStore(pg)
    await store.save(TA, {
      sourceId: SRC_A, sourceHash: 'sh', chunkHash: 'ch', chunkIds: [CH_ACTIVE],
      ingestionAudit: { ingestedAt: new Date().toISOString(), ingestedBy: 'pipe', pipelineVersion: '1', sourceUri: 's3://a' },
      chainOfCustody: [{ stage: 'ingest', actor: 'pipe', at: new Date().toISOString() }],
      manifestHash: 'mh', keyId: 'k1', signature: 'sig', signedAt: new Date().toISOString(),
    })
    expect(await store.countForSource(TA, SRC_A)).toBe(1)
    expect(await store.countForSource(TB, SRC_A)).toBe(0)
  })
})
