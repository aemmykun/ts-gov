import { EvidenceBlock } from './types'

export interface LedgerStore {
  getLatest(tenantId: string): Promise<EvidenceBlock | null>
  append(block: EvidenceBlock): Promise<void>
  updateNextHash(tenantId: string, blockId: string, nextHash: string): Promise<void>
  getRange(tenantId: string, from: number, to: number): Promise<EvidenceBlock[]>
  getByNumber(tenantId: string, blockNumber: number): Promise<EvidenceBlock | null>
}

// Reference in-memory backend. The same interface is implemented by the
// PostgreSQL / file backends (switched via LEDGER_BACKEND) with zero call-site
// change.
export class InMemoryLedgerStore implements LedgerStore {
  private chains: Map<string, EvidenceBlock[]> = new Map()

  private chain(tenantId: string): EvidenceBlock[] {
    let c = this.chains.get(tenantId)
    if (!c) {
      c = []
      this.chains.set(tenantId, c)
    }
    return c
  }

  async getLatest(tenantId: string): Promise<EvidenceBlock | null> {
    const c = this.chain(tenantId)
    return c.length ? c[c.length - 1] : null
  }

  async append(block: EvidenceBlock): Promise<void> {
    this.chain(block.tenantId).push(block)
  }

  async updateNextHash(tenantId: string, blockId: string, nextHash: string): Promise<void> {
    const b = this.chain(tenantId).find(x => x.blockId === blockId)
    if (!b) {
      throw new Error(`LEDGER_STORE: block ${blockId} not found for updateNextHash`)
    }
    b.auditTrail.nextHash = nextHash
  }

  async getRange(tenantId: string, from: number, to: number): Promise<EvidenceBlock[]> {
    return this.chain(tenantId)
      .filter(b => b.blockNumber >= from && b.blockNumber <= to)
      .sort((a, b) => a.blockNumber - b.blockNumber)
  }

  async getByNumber(tenantId: string, blockNumber: number): Promise<EvidenceBlock | null> {
    return this.chain(tenantId).find(b => b.blockNumber === blockNumber) ?? null
  }

  // Test-only helper: mutate a stored block in place WITHOUT recomputing its
  // checksum, simulating tampering. Typed so tests need no `any`.
  tamperBlock(
    tenantId: string,
    blockNumber: number,
    mutate: (block: EvidenceBlock) => void,
  ): void {
    const b = this.chain(tenantId).find(x => x.blockNumber === blockNumber)
    if (!b) throw new Error(`LEDGER_STORE: cannot tamper missing block ${blockNumber}`)
    mutate(b)
  }
}
