# TenantSage — Governance-First AI Retrieval Architecture

> **No Authority → No Retrieval.** Deterministic governance enforcement *before*
> generation, with replayable, tamper-evident evidence.

This repository is the canonical TenantSage reference implementation, aligned to
the canonical Postgres data model in [`schema.sql`](schema.sql). It is a
buildable, fully tested TypeScript project (101 tests). Where the TypeScript
model and `schema.sql` differ, **`schema.sql` is the source of truth**.

## Canonical governance model

```text
tenant_id → family_id → child_id → user_id
```

- **Hierarchy:** tenant → family → child (no organisation/scope layers).
- **Roles:** `staff < supervisor < manager < admin` (level 1–4). Level is used
  only for coarse privilege ordering, never as an evidence-authorization rule.
- **Topic-based authorization:** `policies(tenant_id, role → allowed_topics[])`
  resolves to a subject's `eligibleTopics`; chunks carry a `topic_key`;
  retrieval keeps `topic_key = ANY(eligible_topics)`. There is no
  role-threshold allow-list on evidence.
- **Chunk status:** `ACTIVE` / `REVOKED` / `EXPIRED`.
- **Classification:** `public / internal / confidential / restricted` (closed
  enum, carried on the source/chunk — not a clearance ceiling on the boundary).
- **Evidence ledger:** decision `ALLOW` / `DENY` with `dar_decision_hash`,
  `prompt_hash`, `response_hash`, and a `previous_hash → current_hash` chain.

## Canonical runtime flow

```text
Identity
   ↓  (SSOGate — verified JWT, identity only)
User Assignment Resolution            ← AssignmentResolver (authoritative store)
   ↓
DAR  (DAREngine)                       ← authority resolved from assignments + policies
   ↓
Eligible Evidence Boundary            ← immutable, deterministic (scopes + eligibleTopics)
   ↓
TrustRAG Governed Retrieval           ← searchRagChunksAudited() — fail-closed predicate
   ↓
Approved Evidence Corpus              ← "Ghost Effect" full-governance filter
   ↓
AI Generation                         ← over the approved corpus only
   ↓
Evidence Ledger                       ← ALLOW/DENY, replayable, hash-chained block
```

The whole flow is wired in [`src/TenantSagePipeline.ts`](src/TenantSagePipeline.ts).

## Governance guarantees

| # | Guarantee | Where |
|---|-----------|-------|
| 1 | **Authority from authoritative assignments, not claims.** The JWT claim establishes identity only; family/child scope and role come from `user_assignments`, and `eligibleTopics` from `policies`. No assignment ⇒ empty boundary. | `src/assignments/*`, `src/dar/DAREngine.ts` |
| 2 | **Governance metadata is policy-derived, never defaulted at ingestion.** `classification`, `legalHold`, `validFrom/validTo`, `policyVersion` come from a `GovernancePolicyProvider`; ingestion is refused (fail-closed) when no authoritative policy exists, and a tampered policy (checksum mismatch) is rejected. | `src/policy/GovernancePolicyProvider.ts` |
| 3 | **ApprovedEvidenceCorpus enforces the full governance set** — tenant, family/child scope, topic eligibility, status, legal hold, retention expiry, effective-date window. | `src/runtime/ApprovedEvidenceCorpus.ts` |
| 4 | **HandOff evidence integrity** — source hash, chunk hash, signed manifest (HMAC), ingestion audit record, chain-of-custody — bound into the ledger block checksum. | `src/handoff/*`, `src/ledger/BlockBuilder.ts` |
| 5 | **Fail-closed retrieval.** The DAR boundary compiles into a deterministic `RetrievalPredicate`. `searchRagChunksAudited()` is the single enforcement point: an empty boundary refuses retrieval *before the index is queried*, and the index only exposes a predicate-scoped `searchWithin` — there is no unrestricted vector search. | `src/trustrag/*` |

## Identity ≠ Authority

`TenantClaim` carries identity only (`userId`, `tenantId`, `provider`,
`verifiedAt`). It has **no** `role` / `familyId` — authority is resolved
exclusively from the authoritative `UserAssignment` set via the DAR, so an
`if (claim.role === 'admin')` escalation is impossible by construction. Role
level never bypasses scope: an `admin` assignment to `family-X` grants no access
to `family-Z`. `TenantIsolationGuard.enforceScope(assignments, familyId,
childId?)` checks the assignments, not the claim. Retrieval is boundary-only too:
`searchRagChunksAudited(embedding, topK, boundary)` and
`ApprovedEvidenceCorpus.filter(chunks, boundary)` take no claim.

**Scope-match rule** (shared by the corpus filter and the policy `ScopeCheck`,
in `src/dar/scope.ts`):

```text
familyId == null          → tenant-global evidence: visible to any subject with scopes
scope.childId == null     → family-level grant: sees all children in that family
chunk.childId == null     → family-level evidence: visible to any family member
otherwise                 → exact (familyId, childId) match
```

## Runtime fail-closed invariants (enforced in the pipeline)

```text
No Assignment → No Authority   (DAR returns an empty boundary)
No Authority  → No Retrieval   (boundary.empty throws before the index)
No Evidence   → No Generation  (empty approved corpus throws)
No Policy     → No Ingestion   (binder refuses without authoritative governance)
```

Plus: tenant isolation validates an explicit `requestedTenantId` (not the no-op
`claim.tenantId` vs `claim.tenantId`), policy is evaluated *before* retrieval via
an injected `PolicyDecisionProvider`, and every ledger block is stamped with
`decision`, `darDecisionHash`, `authoritySnapshotId`, `policyVersion`, and a
`boundaryHash` (bound into the tamper-evident checksum).

## Governance replay (why, not just what)

`replayBlock()` returns the block's `decision` and `authority` evidence
(`authoritySnapshotId` + `policyVersion` + `boundaryHash`) alongside the
recomputed checksum — so a replay answers **"why was this allowed/denied?"**, not
just **"what happened / was it altered?"**. `verifyFromGenesis(tenantId,
expectedGenesisChecksum?)` proves the entire chain from block 1 with no gaps,
optionally pinned to an externally-attested genesis checksum.

```ts
interface EvidenceBoundary {
  tenantId: string
  scopes: { familyId: string | null; childId: string | null }[]
  eligibleTopics: string[]
  allowedStatuses: ChunkStatus[]        // ['ACTIVE']
  roleLevel: number                     // staff=1 … admin=4
  authoritySnapshotId: string; policyVersion: string
  effectiveAt: string; computedAt: string; empty: boolean
}
```

## Layers

- **Identity** — `SSOGate` (alg-pinned JWT verification), `TenantIsolationGuard`.
- **Assignments** — authoritative `AssignmentResolver` (source of authority).
- **Policy** — 7-gate `PolicyEngine` (tenant boundary → scope → topic permission
  → status → legal hold → retention → effective date) + topic-based
  `TopicPolicyProvider` + ingestion `GovernancePolicyProvider`.
- **DAR** — `DAREngine` produces the immutable `EvidenceBoundary`.
- **TrustRAG** — `TrustRAGRetriever.searchRagChunksAudited()` governs retrieval.
- **Runtime** — `ApprovedEvidenceCorpus` ("Ghost Effect").
- **HandOff** — signed evidence-integrity manifests.
- **Ledger** — `EvidenceLedger` / `BlockBuilder` / `ChainVerifier` /
  `ReplayEngine` (ALLOW/DENY, hash-chained, replayable).

## Develop

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # jest (101 tests)
npm run test:coverage
npm run build       # emit to dist/
```
