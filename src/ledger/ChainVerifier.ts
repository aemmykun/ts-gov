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
      requestId:        b.requestId,
      blockNumber:      b.blockNumber,
      tenantId:         b.tenantId,
      createdAt:        b.createdAt,
      decision:         b.decision,
      darDecisionHash:  b.darDecisionHash,
      userIdentity:     b.userIdentity,
      retrievedEvidenceIds: b.retrievedEvidenceIds,
      promptHash:       b.promptHash,
      responseHash:     b.responseHash,
      aiOutput:         b.aiOutput,
      handoff:          b.handoff ?? null,
      authority:        b.authority ?? null,
      dataJson:         b.dataJson,
      previousHash:     b.auditTrail.previousHash,
    }))
  }

  // Forensic anchor: prove the whole chain from block 1 with no gaps. The first
  // block must be a genesis block (prevBlockHash === 'GENESIS'), optionally
  // pinned to an externally-attested checksum.
  async verifyFromGenesis(
    tenantId: string,
    expectedGenesisChecksum?: string,
  ): Promise<ChainVerifyResult> {
    const blocks = await this.store.getRange(tenantId, 1, Number.MAX_SAFE_INTEGER)

    if (blocks.length === 0) {
      return { valid: true, totalBlocks: 0 }
    }

    const first = blocks[0]
    if (first.blockNumber !== 1 || first.auditTrail.previousHash !== 'GENESIS') {
      return {
        valid:       false,
        totalBlocks: blocks.length,
        brokenAt:    first.blockNumber,
        reason:      'Chain does not start at a genesis block (gap before block 1)',
      }
    }
    if (expectedGenesisChecksum && first.auditTrail.currentHash !== expectedGenesisChecksum) {
      return {
        valid:       false,
        totalBlocks: blocks.length,
        brokenAt:    1,
        reason:      'Genesis checksum does not match the attested anchor',
      }
    }

    return this.verify(tenantId, 1, blocks[blocks.length - 1].blockNumber)
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
      if (recomputed !== block.auditTrail.currentHash) {
        return {
          valid:       false,
          totalBlocks: blocks.length,
          brokenAt:    block.blockNumber,
          reason:      `Checksum mismatch at block ${block.blockNumber}`,
        }
      }

      // 2. Linkage integrity (skipped for the first block of the range, whose
      //    predecessor may be outside [from, to]).
      if (expectedPrevHash !== null && block.auditTrail.previousHash !== expectedPrevHash) {
        return {
          valid:       false,
          totalBlocks: blocks.length,
          brokenAt:    block.blockNumber,
          reason:      `Broken prev-hash link at block ${block.blockNumber}`,
        }
      }

      expectedPrevHash = block.auditTrail.currentHash
    }

    return { valid: true, totalBlocks: blocks.length }
  }
}
