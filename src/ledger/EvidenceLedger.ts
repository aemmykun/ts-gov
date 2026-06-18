import { BlockBuilder, BlockInput } from './BlockBuilder'
import { LedgerStore }              from './LedgerStore'
import { ChainVerifier }            from './ChainVerifier'
import { ReplayEngine }             from './ReplayEngine'
import { EvidenceBlock, ReplayResult, ChainVerifyResult } from './types'

export class EvidenceLedger {
  private builder:  BlockBuilder
  verifier:         ChainVerifier
  replay:           ReplayEngine

  // QA FIX 1: In-process commit mutex — prevents race condition where two simultaneous
  // commits both read the same prevBlock and create forked chains
  private commitLocks: Map<string, Promise<EvidenceBlock>> = new Map()

  constructor(private store: LedgerStore) {
    this.builder  = new BlockBuilder()
    this.verifier = new ChainVerifier(store)
    this.replay   = new ReplayEngine(store, this.verifier)
  }

  async commit(
    input: Omit<BlockInput, 'prevBlock' | 'blockNumber'>
  ): Promise<EvidenceBlock> {
    const tenantId = input.claim.tenantId

    // QA FIX 2: Chain commits per tenant — wait for any in-flight commit to finish first
    const existing = this.commitLocks.get(tenantId) ?? Promise.resolve(null as any)
    const next = existing.catch(() => null).then(() => this._doCommit(input))
    this.commitLocks.set(tenantId, next)
    return next
  }

  private async _doCommit(
    input: Omit<BlockInput, 'prevBlock' | 'blockNumber'>
  ): Promise<EvidenceBlock> {
    const tenantId  = input.claim.tenantId
    const prevBlock = await this.store.getLatest(tenantId)
    const blockNumber = prevBlock ? prevBlock.blockNumber + 1 : 1

    const newBlock = this.builder.build({ ...input, prevBlock, blockNumber })

    await this.store.append(newBlock)

    // QA FIX 3: updateNextHash failure must NOT break the new block commit
    // — it's a best-effort backward pointer; chain integrity is proven via prevHash
    if (prevBlock) {
      await this.store.updateNextHash(
        prevBlock.blockId,
        newBlock.auditTrail.currentHash
      ).catch(err =>
        console.error(`[LEDGER] updateNextHash failed for block ${prevBlock.blockId}:`, err)
      )
    }

    return newBlock
  }

  async verifyChain(
    tenantId: string, from: number, to: number
  ): Promise<ChainVerifyResult> {
    return this.verifier.verify(tenantId, from, to)
  }

  // Forensic full-chain verification anchored at genesis (no gaps from block 1).
  async verifyFromGenesis(
    tenantId: string, expectedGenesisChecksum?: string
  ): Promise<ChainVerifyResult> {
    return this.verifier.verifyFromGenesis(tenantId, expectedGenesisChecksum)
  }

  async replayBlock(tenantId: string, blockNumber: number): Promise<ReplayResult> {
    return this.replay.replay(tenantId, blockNumber)
  }
}
