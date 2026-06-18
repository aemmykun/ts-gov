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

export interface PipelineRequest {
  claim:     TenantClaim
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

// Canonical runtime flow (correction-aligned):
//
//   Identity
//     → User Assignment Resolution
//     → DAR
//     → Eligible Evidence Boundary
//     → TrustRAG Governed Retrieval
//     → Approved Evidence Corpus
//     → AI Generation
//     → Evidence Ledger
//
// Deterministic enforcement happens BEFORE generation; nothing is generated
// without authority, and every run is recorded as a replayable ledger block.
export class TenantSagePipeline {
  constructor(
    private guard: TenantIsolationGuard,
    private dar: DAREngine,
    private retriever: TrustRAGRetriever,
    private ledger: EvidenceLedger,
    private generate: GenerationFn,
  ) {}

  async run(req: PipelineRequest): Promise<PipelineResult> {
    // 1. Identity → tenant isolation (defence in depth before authority).
    this.guard.enforce(req.claim, req.claim.tenantId)

    // 2/3/4. Assignment resolution → DAR → eligible evidence boundary.
    const boundary = await this.dar.resolve(req.claim)

    // 5/6. TrustRAG governed retrieval → approved evidence corpus.
    //      Fail-closed: an empty boundary throws before the index is touched.
    const retrieval = await this.retriever.retrieve(
      req.embedding, req.topK, req.claim, boundary, req.filterOptions,
    )

    // 7. AI generation over the approved corpus only.
    const gen = await this.generate(req.query, retrieval.chunks)

    // 8. Evidence ledger — replayable, tamper-evident record of the decision.
    const policyResult: PolicyCheckResult = { passed: true }
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
    })

    return { boundary, chunks: retrieval.chunks, response: gen.response, block }
  }
}
