# TenantSage — Governance-First AI Retrieval Architecture

> **No Authority → No Retrieval.** Deterministic governance enforcement *before*
> generation, with replayable, tamper-evident evidence.

This repository is the canonical TenantSage reference implementation, revised to
close the governance-model gaps identified in architecture review. It is a
buildable, fully tested TypeScript project (98 tests).

## Canonical runtime flow

```text
Identity
   ↓  (SSOGate — verified JWT, identity only)
User Assignment Resolution            ← AssignmentResolver (authoritative store)
   ↓
DAR  (DAREngine)                       ← authority resolved from assignments
   ↓
Eligible Evidence Boundary            ← immutable, deterministic
   ↓
TrustRAG Governed Retrieval           ← fail-closed predicate; no open search
   ↓
Approved Evidence Corpus              ← "Ghost Effect" full-governance filter
   ↓
AI Generation                         ← over the approved corpus only
   ↓
Evidence Ledger                       ← replayable, hash-chained block
```

The whole flow is wired in [`src/TenantSagePipeline.ts`](src/TenantSagePipeline.ts).

## Governance corrections applied

| # | Correction | Where |
|---|------------|-------|
| 1 | **Authority from authoritative assignments, not claims.** The JWT claim establishes identity only; role / family / scope authority is resolved `user → user_assignments → memberships → DAR`. No assignment ⇒ empty boundary. | `src/assignments/*`, `src/dar/DAREngine.ts` |
| 2 | **Governance metadata is policy-derived, never defaulted at ingestion.** `retainUntil`, `effectiveTo`, `allowedRoles`, `visibility`, `legalHold`, `classification`, `sensitivity`, `status` come from a `GovernancePolicyProvider`; ingestion is refused (fail-closed) when no authoritative policy exists. | `src/policy/GovernancePolicyProvider.ts` |
| 3 | **ApprovedEvidenceCorpus enforces the full governance set** — tenant, family, lifecycle status, role hierarchy, **legal hold, retention expiry, effective-date window, classification, sensitivity**. Optional `strict` mode rejects chunks missing required metadata. | `src/runtime/ApprovedEvidenceCorpus.ts` |
| 4 | **HandOff evidence integrity** beyond a checksum: **source hash, chunk hash, signed manifest (HMAC), ingestion audit record, chain-of-custody**. The manifest is bound into the ledger block checksum. | `src/handoff/*`, `src/ledger/BlockBuilder.ts` |
| 5 | **Fail-closed retrieval.** The DAR boundary is compiled into a deterministic `RetrievalPredicate`. An empty boundary refuses retrieval *before the index is queried*; the index only exposes a predicate-scoped `searchWithin` — there is no unrestricted vector search. | `src/trustrag/*` |

## Audit-grade evidence boundary

Follow-up review hardened the `EvidenceBoundary` from access-control-grade to
audit-grade:

- **Organisation & scope dimensions** — `organisationIds` / `scopeIds` flow
  `tenant → organisation → scope → family` from the assignment, and are enforced
  in the corpus and retrieval predicate.
- **Classification & sensitivity are closed enums** (`Classification`,
  `Sensitivity`) with tier-ordered, case-insensitive comparison — no free text.
- **Replayable** — every boundary carries `authoritySnapshotId`
  (`assignmentId@assignmentVersion`) and `policyVersion`, so any historical DAR
  decision can prove which assignment set and which policy produced it.
- **No magic strings** — owner tenant-wide access is an explicit
  `allFamilies: boolean`, never `familyId === '*'`.

```ts
interface EvidenceBoundary {
  tenantIds: string[]; organisationIds: string[]; scopeIds: string[]
  familyIds: string[]; allFamilies: boolean
  allowedStatuses: DocumentStatus[]; allowedRoles: Role[]
  classificationLevel: Classification; sensitivityLevel: Sensitivity
  authoritySnapshotId: string; policyVersion: string
  effectiveAt: string; computedAt: string; empty: boolean
}
```

## Layers

- **Identity** — `SSOGate` (alg-pinned JWT verification), `TenantIsolationGuard`.
- **Assignments** — authoritative `AssignmentResolver` (source of authority).
- **Policy** — 4-gate `PolicyEngine` (retention → legal hold → role → effective
  date) + `GovernancePolicyProvider`.
- **DAR** — `DAREngine` produces the immutable `EvidenceBoundary`.
- **TrustRAG** — `TrustRAGRetriever` governs retrieval via predicates.
- **Runtime** — `ApprovedEvidenceCorpus` ("Ghost Effect").
- **HandOff** — signed evidence-integrity manifests.
- **Ledger** — `EvidenceLedger` / `BlockBuilder` / `ChainVerifier` /
  `ReplayEngine` (hash-chained, replayable).

## Develop

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # jest (91 tests)
npm run test:coverage
npm run build       # emit to dist/
```

## Note on test changes

The corrected authority model intentionally diverges from a few assertions in
the original suite that derived authority from JWT claims (the exact behaviour
being corrected). Those Layer-5 tests now seed authoritative **assignments**
instead of relying on claim fields; their *intent* (owner wildcard, admin own
family, status visibility, viewer denial) is preserved, and new tests assert
that a claim cannot escalate beyond its authoritative assignment.
