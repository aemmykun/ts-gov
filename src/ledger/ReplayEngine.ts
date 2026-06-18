import { LedgerStore } from './LedgerStore'
import { ChainVerifier } from './ChainVerifier'
import { EvidenceBlock, ReplayResult } from './types'

export class ReplayEngine {
  constructor(private store: LedgerStore, private verifier: ChainVerifier) {}

  async replay(tenantId: string, blockNumber: number): Promise<ReplayResult> {
    const block = await this.store.getByNumber(tenantId, blockNumber)
    if (!block) {
      throw new Error(`REPLAY: block ${blockNumber} not found for tenant ${tenantId}`)
    }

    const recomputed = this.verifier.recomputeChecksum(block)
    const chainIntegrity = recomputed === block.auditTrail.blockChecksum ? 'valid' : 'broken'

    return {
      blockNumber,
      policyDecision: this.decision(block),
      chainIntegrity,
      recomputedChecksum: recomputed,
      storedChecksum:     block.auditTrail.blockChecksum,
    }
  }

  // The recorded policy outcome is recoverable deterministically from the block.
  private decision(block: EvidenceBlock): 'approved' | 'denied' {
    const p = block.policyRules
    const approved =
      p.retentionCheck === 'passed' &&
      p.roleCheck === 'passed' &&
      p.effectiveDateCheck === 'passed' &&
      p.legalHold === false
    return approved ? 'approved' : 'denied'
  }
}
