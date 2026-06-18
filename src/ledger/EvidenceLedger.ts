import { BlockBuilder, BlockInput } from './BlockBuilder'
import { LedgerStore }              from './LedgerStore'
import { ChainVerifier }            from './ChainVerifier'
import { ReplayEngine }             from './ReplayEngine'
import { LedgerLock, InProcessLedgerLock } from './LedgerLock'
import { EvidenceBlock, ReplayResult, ChainVerifyResult } from './types'

export class EvidenceLedger {
  private builder:  BlockBuilder
  verifier:         ChainVerifier
  replay:           ReplayEngine

  // Per-tenant commit lock — prevents a race where two simultaneous commits read
  // the same prevBlock and fork the chain. Defaults to an in-process mutex;
  // inject a Postgres advisory-lock implementation for distributed safety.
  private lock: LedgerLock

  constructor(private store: LedgerStore, lock: LedgerLock = new InProcessLedgerLock()) {
    this.builder  = new BlockBuilder()
    this.verifier = new ChainVerifier(store)
    this.replay   = new ReplayEngine(store, this.verifier)
    this.lock     = lock
  }

  async commit(
    input: Omit<BlockInput, 'prevBlock' | 'blockNumber'>
  ): Promise<EvidenceBlock> {
    return this.lock.withLock(input.claim.tenantId, () => this._doCommit(input))
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
        tenantId,
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
