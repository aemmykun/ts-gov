import { HandOffManifest } from '../handoff/types'

export interface EvidenceBlock {
  blockId:     string
  blockNumber: number
  createdAt:   string

  userIdentity: {
    userId:     string
    tenantId:   string
    provider:   string
    verifiedAt: number
  }

  policyRules: {
    ruleVersion:        string
    retentionCheck:     'passed' | 'failed'
    legalHold:          boolean
    roleCheck:          'passed' | 'failed'
    effectiveDateCheck: 'passed' | 'failed'
  }

  contextRetrieved: {
    documentIds:    string[]
    chunkIds:       string[]
    provenanceHash: string
  }

  aiOutput: {
    responseHash: string
    modelUsed:    string
    tokenCount:   number
  }

  // Correction #4: optional evidence-integrity manifest binding the retrieved
  // context to its source via source/chunk hashes, a signed manifest and a
  // chain-of-custody record.
  handoff?: HandOffManifest

  // Replay provenance: proves which authority snapshot, which policy version and
  // the exact boundary that produced this decision — so it can be reproduced
  // years later from immutable evidence. null only for legacy/minimal commits.
  authority: {
    authoritySnapshotId: string
    policyVersion:       string
    boundaryHash:        string
  } | null

  auditTrail: {
    queryHash:     string
    prevBlockHash: string
    nextBlockHash: string | null
    blockChecksum: string
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
  policyDecision: 'approved' | 'denied'
  chainIntegrity: 'valid' | 'broken'
  recomputedChecksum: string
  storedChecksum:     string
}
