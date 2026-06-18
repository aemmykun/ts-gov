import crypto from 'crypto'
import { EvidenceBlock } from './types'
import { TenantClaim }   from '../identity/types'
import { HandOffManifest } from '../handoff/types'

export interface BlockInput {
  claim:        TenantClaim
  requestId:    string
  decision:     'ALLOW' | 'DENY'
  // Hash of the DAR decision (resolved boundary) behind this outcome.
  darDecisionHash: string
  retrievedEvidenceIds: string[]
  promptText:   string
  responseText: string
  modelUsed?:   string
  tokenCount?:  number
  dataJson?:    Record<string, unknown>
  prevBlock:    EvidenceBlock | null
  blockNumber:  number
  handoff?:     HandOffManifest
  // Replay provenance (audit-grade). Bound into the block checksum.
  authoritySnapshotId?: string
  policyVersion?:       string
  boundaryHash?:        string
}

export class BlockBuilder {
  build(input: BlockInput): EvidenceBlock {
    const blockId   = crypto.randomUUID()
    const createdAt = new Date().toISOString()

    const userIdentity: EvidenceBlock['userIdentity'] = {
      userId:     input.claim.userId,
      tenantId:   input.claim.tenantId,
      provider:   input.claim.provider,
      verifiedAt: input.claim.verifiedAt,
    }

    const promptHash   = input.promptText   ? this.sha256(input.promptText)   : null
    const responseHash = input.responseText ? this.sha256(input.responseText) : null

    const aiOutput: EvidenceBlock['aiOutput'] =
      input.modelUsed !== undefined || input.tokenCount !== undefined
        ? { modelUsed: input.modelUsed ?? '', tokenCount: input.tokenCount ?? 0 }
        : null

    const authority: EvidenceBlock['authority'] =
      input.authoritySnapshotId || input.policyVersion || input.boundaryHash
        ? {
            authoritySnapshotId: input.authoritySnapshotId ?? '',
            policyVersion:       input.policyVersion ?? '',
            boundaryHash:        input.boundaryHash ?? '',
          }
        : null

    const previousHash = input.prevBlock
      ? input.prevBlock.auditTrail.currentHash
      : 'GENESIS'

    const handoff  = input.handoff ?? null
    const dataJson = input.dataJson ?? {}

    // Canonical JSON for the checksum — keys sorted so order never affects the hash.
    const currentHash = this.sha256(this.canonicalJson({
      blockId,
      requestId:   input.requestId,
      blockNumber: input.blockNumber,
      tenantId:    input.claim.tenantId,
      createdAt,
      decision:        input.decision,
      darDecisionHash: input.darDecisionHash,
      userIdentity,
      retrievedEvidenceIds: input.retrievedEvidenceIds,
      promptHash,
      responseHash,
      aiOutput,
      handoff,     // custody metadata bound into the checksum
      authority,   // replay provenance bound into the checksum
      dataJson,
      previousHash,
    }))

    const block: EvidenceBlock = {
      blockId,
      requestId:   input.requestId,
      blockNumber: input.blockNumber,
      tenantId:    input.claim.tenantId,
      createdAt,
      decision:        input.decision,
      darDecisionHash: input.darDecisionHash,
      userIdentity,
      retrievedEvidenceIds: input.retrievedEvidenceIds,
      promptHash,
      responseHash,
      aiOutput,
      authority,
      dataJson,
      auditTrail: {
        previousHash,
        currentHash,
        nextHash: null,
      },
    }

    if (input.handoff) block.handoff = input.handoff

    return block
  }

  // Stable canonical JSON — sorts all keys recursively.
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
