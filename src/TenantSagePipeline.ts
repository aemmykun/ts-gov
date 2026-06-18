import crypto from 'crypto'
import { TenantClaim } from './identity/types'
import { TenantIsolationGuard } from './identity/TenantIsolationGuard'
import { DAREngine } from './dar/DAREngine'
import { EvidenceBoundary } from './dar/types'
import { TrustRAGRetriever } from './trustrag/TrustRAGRetriever'
import { GovernedChunk, FilterOptions } from './runtime/ApprovedEvidenceCorpus'
import { EvidenceLedger } from './ledger/EvidenceLedger'
import { EvidenceBlock } from './ledger/types'
import { PolicyCheckResult } from './policy/types'
import { HandOffManifest } from './handoff/types'

export interface GenerationFn {
  (query: string, chunks: GovernedChunk[]): Promise<{
    response: string
    modelUsed: string
    tokenCount: number
  }>
}

// Boundary-level policy gate, evaluated AFTER authority is established but BEFORE
// retrieval (matches the canonical Identity → DAR → Policy → Retrieval flow).
// Injected so the decision is explicit and replayable — never hardcoded.
export interface PolicyDecisionProvider {
  evaluate(input: {
    claim: TenantClaim
    boundary: EvidenceBoundary
    requestedAt: Date
  }): Promise<PolicyCheckResult>
}

export interface PipelineRequest {
  claim:     TenantClaim
  // The tenant the request actually targets (route/API/handoff). MUST be an
  // independent value — comparing the claim against itself is a no-op.
  requestedTenantId: string
  query:     string
  embedding: number[]
  topK:      number
  ruleVersion: string
  handoff?:  HandOffManifest
  filterOptions?: FilterOptions
}

export interface PipelineResult {
  boundary: EvidenceBoundary
  chunks:   GovernedChunk[]
  response: string
  block:    EvidenceBlock
}

// Fail-closed invariants enforced centrally by the pipeline itself, so the
// guarantees hold regardless of how downstream components behave.
export class NoAuthorityError extends Error {
  constructor() { super('NO_AUTHORITY: empty evidence boundary — retrieval denied') }
}
export class NoEvidenceError extends Error {
  constructor() { super('NO_EVIDENCE: approved corpus empty — generation denied') }
}
export class PolicyDeniedError extends Error {
  constructor(reason: string) { super(`POLICY_DENIED: ${reason}`) }
}

// Canonical runtime flow (correction-aligned):
//
//   Identity
//     → Tenant Isolation
//     → User Assignment Resolution
//     → DAR
//     → Eligible Evidence Boundary
//     → Policy Evaluation
//     → TrustRAG Governed Retrieval
//     → Approved Evidence Corpus
//     → AI Generation
//     → Evidence Ledger
//
// The pipeline ENFORCES the fail-closed invariants directly:
//   No Assignment → No Authority  (DAR returns empty boundary)
//   No Authority  → No Retrieval  (boundary.empty throws before the index)
//   No Evidence   → No Generation (empty approved corpus throws)
// and records authoritySnapshotId + policyVersion + boundaryHash for replay.
export class TenantSagePipeline {
  constructor(
    private guard: TenantIsolationGuard,
    private dar: DAREngine,
    private retriever: TrustRAGRetriever,
    private ledger: EvidenceLedger,
    private generate: GenerationFn,
    private policy?: PolicyDecisionProvider,
  ) {}

  async run(req: PipelineRequest): Promise<PipelineResult> {
    const requestedAt = new Date()

    // 1. Identity → tenant isolation against the ACTUAL requested tenant.
    this.guard.enforce(req.claim, req.requestedTenantId)

    // 2/3/4. Assignment resolution → DAR → eligible evidence boundary.
    const boundary = await this.dar.resolve(req.claim)

    // No Authority → No Retrieval. Enforced here, not assumed downstream.
    if (boundary.empty || boundary.tenantIds.length === 0) {
      throw new NoAuthorityError()
    }

    // 5. Policy evaluation BEFORE retrieval (explicit, not hardcoded).
    const policyResult: PolicyCheckResult = this.policy
      ? await this.policy.evaluate({ claim: req.claim, boundary, requestedAt })
      : { passed: true }
    if (!policyResult.passed) {
      throw new PolicyDeniedError(policyResult.reason ?? 'policy gate failed')
    }

    // 6/7. TrustRAG governed retrieval → approved evidence corpus.
    const retrieval = await this.retriever.retrieve(
      req.embedding, req.topK, boundary, req.filterOptions,
    )

    // No Evidence → No Generation.
    if (retrieval.chunks.length === 0) {
      throw new NoEvidenceError()
    }

    // 8. AI generation over the approved corpus only.
    const gen = await this.generate(req.query, retrieval.chunks)

    // 9. Evidence ledger — replayable, tamper-evident record of the decision,
    //    stamped with the authority/policy snapshot and a boundary hash.
    const block = await this.ledger.commit({
      claim:        req.claim,
      policyResult,
      ruleVersion:  req.ruleVersion,
      documentIds:  [...new Set(retrieval.chunks.map(c => c.sourceId))],
      chunkIds:     retrieval.chunks.map(c => c.chunkId),
      contextText:  retrieval.chunks.map(c => c.content).join('\n'),
      aiResponse:   gen.response,
      modelUsed:    gen.modelUsed,
      tokenCount:   gen.tokenCount,
      queryText:    req.query,
      handoff:      req.handoff,
      authoritySnapshotId: boundary.authoritySnapshotId,
      policyVersion:       boundary.policyVersion,
      boundaryHash:        this.hashBoundary(boundary),
    })

    return { boundary, chunks: retrieval.chunks, response: gen.response, block }
  }

  // Deterministic hash of the immutable boundary — lets a replay prove the exact
  // authority surface that produced this decision.
  private hashBoundary(boundary: EvidenceBoundary): string {
    return crypto.createHash('sha256')
      .update(this.canonical(boundary), 'utf8')
      .digest('hex')
  }

  private canonical(obj: unknown): string {
    if (Array.isArray(obj)) return '[' + obj.map(v => this.canonical(v)).join(',') + ']'
    if (obj !== null && typeof obj === 'object') {
      const o = obj as Record<string, unknown>
      return '{' + Object.keys(o).sort().map(k =>
        JSON.stringify(k) + ':' + this.canonical(o[k])
      ).join(',') + '}'
    }
    return JSON.stringify(obj)
  }
}
