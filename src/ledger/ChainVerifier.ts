import { BlockBuilder } from './BlockBuilder'
import { LedgerStore } from './LedgerStore'
import { EvidenceBlock, ChainVerifyResult } from './types'

export class ChainVerifier {
  private hasher = new BlockBuilder()

  constructor(private store: LedgerStore) {}

  // Recompute a block's checksum from its content exactly as BlockBuilder did.
  // Any field mutation produces a different checksum → tamper-evident.
  recomputeChecksum(b: EvidenceBlock): string {
    return this.hasher.sha256(this.hasher.canonicalJson({
      blockId:          b.blockId,
      blockNumber:      b.blockNumber,
      createdAt:        b.createdAt,
      userIdentity:     b.userIdentity,
      policyRules:      b.policyRules,
      contextRetrieved: b.contextRetrieved,
      aiOutput:         b.aiOutput,
      handoff:          b.handoff ?? null,
      authority:        b.authority ?? null,
      queryHash:        b.auditTrail.queryHash,
      prevBlockHash:    b.auditTrail.prevBlockHash,
    }))
  }

  async verify(tenantId: string, from: number, to: number): Promise<ChainVerifyResult> {
    const blocks = await this.store.getRange(tenantId, from, to)

    if (blocks.length === 0) {
      return { valid: true, totalBlocks: 0 }
    }

    let expectedPrevHash: string | null = null

    for (const block of blocks) {
      // 1. Content integrity.
      const recomputed = this.recomputeChecksum(block)
      if (recomputed !== block.auditTrail.blockChecksum) {
        return {
          valid:       false,
          totalBlocks: blocks.length,
          brokenAt:    block.blockNumber,
          reason:      `Checksum mismatch at block ${block.blockNumber}`,
        }
      }

      // 2. Linkage integrity (skipped for the first block of the range, whose
      //    predecessor may be outside [from, to]).
      if (expectedPrevHash !== null && block.auditTrail.prevBlockHash !== expectedPrevHash) {
        return {
          valid:       false,
          totalBlocks: blocks.length,
          brokenAt:    block.blockNumber,
          reason:      `Broken prev-hash link at block ${block.blockNumber}`,
        }
      }

      expectedPrevHash = block.auditTrail.blockChecksum
    }

    return { valid: true, totalBlocks: blocks.length }
  }
}
