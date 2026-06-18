import crypto from 'crypto'
import { EvidenceBlock } from './types'
import { TenantClaim }   from '../identity/types'
import { PolicyCheckResult } from '../policy/types'
import { HandOffManifest } from '../handoff/types'

export interface BlockInput {
  claim:        TenantClaim
  policyResult: PolicyCheckResult
  ruleVersion:  string
  documentIds:  string[]
  chunkIds:     string[]
  contextText:  string
  aiResponse:   string
  modelUsed:    string
  tokenCount:   number
  queryText:    string
  prevBlock:    EvidenceBlock | null
  blockNumber:  number
  handoff?:     HandOffManifest
}

export class BlockBuilder {
  build(input: BlockInput): EvidenceBlock {
    const blockId   = crypto.randomUUID()
    const createdAt = new Date().toISOString()

    const userIdentity: EvidenceBlock['userIdentity'] = {
      userId:     input.claim.userId,
      tenantId:   input.claim.tenantId,
      provider:   input.claim.provider,
      verifiedAt: input.claim.verifiedAt
    }

    const policyRules: EvidenceBlock['policyRules'] = {
      ruleVersion:        input.ruleVersion,
      retentionCheck:     input.policyResult.failedAt === 'retention'       ? 'failed' : 'passed',
      legalHold:          input.policyResult.failedAt === 'legal_hold',
      roleCheck:          input.policyResult.failedAt === 'role_permission'  ? 'failed' : 'passed',
      effectiveDateCheck: input.policyResult.failedAt === 'effective_date'   ? 'failed' : 'passed'
    }

    const contextRetrieved: EvidenceBlock['contextRetrieved'] = {
      documentIds:    input.documentIds,
      chunkIds:       input.chunkIds,
      provenanceHash: this.sha256(input.contextText)
    }

    const aiOutput: EvidenceBlock['aiOutput'] = {
      responseHash: this.sha256(input.aiResponse),  // QA: never store raw response
      modelUsed:    input.modelUsed,
      tokenCount:   input.tokenCount
    }

    const prevBlockHash = input.prevBlock
      ? input.prevBlock.auditTrail.blockChecksum
      : 'GENESIS'

    const queryHash = this.sha256(input.queryText)

    const handoff = input.handoff ?? null

    // QA FIX 1: Canonical JSON for checksum — sort keys so order doesn't affect hash
    // Original used JSON.stringify with arbitrary key order — unstable across JS engines
    const blockChecksum = this.sha256(this.canonicalJson({
      blockId,
      blockNumber: input.blockNumber,
      createdAt,
      userIdentity,
      policyRules,
      contextRetrieved,
      aiOutput,
      handoff,        // bound into the checksum so custody metadata is tamper-evident
      queryHash,
      prevBlockHash
    }))

    const block: EvidenceBlock = {
      blockId,
      blockNumber: input.blockNumber,
      createdAt,
      userIdentity,
      policyRules,
      contextRetrieved,
      aiOutput,
      auditTrail: {
        queryHash,
        prevBlockHash,
        nextBlockHash: null,
        blockChecksum
      }
    }

    if (input.handoff) block.handoff = input.handoff

    return block
  }

  // QA FIX 2: Stable canonical JSON — sorts all keys recursively
  canonicalJson(obj: unknown): string {
    if (Array.isArray(obj)) {
      return '[' + obj.map(v => this.canonicalJson(v)).join(',') + ']'
    }
    if (obj !== null && typeof obj === 'object') {
      const sorted = Object.keys(obj as Record<string, unknown>).sort()
      return '{' + sorted.map(k =>
        JSON.stringify(k) + ':' + this.canonicalJson((obj as Record<string, unknown>)[k])
      ).join(',') + '}'
    }
    return JSON.stringify(obj)
  }

  sha256(data: string): string {
    return crypto.createHash('sha256').update(data, 'utf8').digest('hex')
  }
}
