import { HandOffManifest } from '../handoff/types'

// Append-only evidence-ledger block (mirrors the SQL `evidence_ledger` table).
// Each block records a single governance decision (ALLOW/DENY) and is chained to
// its predecessor via previousHash/currentHash, making the chain tamper-evident.
export interface EvidenceBlock {
  blockId:     string   // id
  requestId:   string
  blockNumber: number
  tenantId:    string
  createdAt:   string

  // The governance decision. ALLOW = evidence was governed and released to
  // generation; DENY = the request was refused by the authority/policy layer.
  decision:        'ALLOW' | 'DENY'
  // Hash of the DAR decision (the resolved boundary) that produced this outcome.
  darDecisionHash: string

  userIdentity: {
    userId:     string
    tenantId:   string
    provider:   string
    verifiedAt: number
  }

  // Ids of the chunks released to generation (evidence_ledger.retrieved_evidence_ids).
  retrievedEvidenceIds: string[]
  promptHash:   string | null
  responseHash: string | null

  // Generation metadata (never the raw prompt/response — only hashes above).
  aiOutput: {
    modelUsed:  string
    tokenCount: number
  } | null

  // Optional evidence-integrity manifest binding retrieved context to its source.
  handoff?: HandOffManifest

  // Replay provenance: proves which authority snapshot, which policy version and
  // the exact boundary that produced this decision. null only for minimal commits.
  authority: {
    authoritySnapshotId: string
    policyVersion:       string
    boundaryHash:        string
  } | null

  // Free-form structured payload (evidence_ledger.data_json).
  dataJson: Record<string, unknown>

  auditTrail: {
    previousHash: string        // 'GENESIS' for the first block
    currentHash:  string        // checksum over the canonical block content
    nextHash:     string | null // best-effort forward pointer
  }
}

export interface ChainVerifyResult {
  valid:       boolean
  totalBlocks: number
  brokenAt?:   number
  reason?:     string
}

export interface ReplayResult {
  blockNumber:    number
  decision:       'ALLOW' | 'DENY'
  chainIntegrity: 'valid' | 'broken'
  recomputedChecksum: string
  storedChecksum:     string
  // Authority evidence — lets a replay answer "why was this allowed/denied?".
  authority: {
    authoritySnapshotId: string
    policyVersion:       string
    boundaryHash:        string
  } | null
}
