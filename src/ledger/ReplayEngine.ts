import { LedgerStore } from './LedgerStore'
import { ChainVerifier } from './ChainVerifier'
import { ReplayResult } from './types'

export class ReplayEngine {
  constructor(private store: LedgerStore, private verifier: ChainVerifier) {}

  async replay(tenantId: string, blockNumber: number): Promise<ReplayResult> {
    const block = await this.store.getByNumber(tenantId, blockNumber)
    if (!block) {
      throw new Error(`REPLAY: block ${blockNumber} not found for tenant ${tenantId}`)
    }

    const recomputed = this.verifier.recomputeChecksum(block)
    const chainIntegrity = recomputed === block.auditTrail.currentHash ? 'valid' : 'broken'

    return {
      blockNumber,
      decision:           block.decision,
      chainIntegrity,
      recomputedChecksum: recomputed,
      storedChecksum:     block.auditTrail.currentHash,
      // Surface the authority provenance so the replay proves *why* the decision
      // was permitted, not merely that the record is intact.
      authority:          block.authority ?? null,
    }
  }
}
