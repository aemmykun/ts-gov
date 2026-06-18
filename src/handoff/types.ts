// Correction #4: a checksum alone is insufficient. The HandOff manifest binds
// retrieved evidence to its origin with: source hash, chunk hash, a signed
// manifest, an ingestion audit record and chain-of-custody metadata.

export interface IngestionAudit {
  ingestedAt:      string
  ingestedBy:      string   // pipeline / service identity
  pipelineVersion: string
  sourceUri:       string
}

export interface CustodyEvent {
  stage:  string   // e.g. 'ingest', 'chunk', 'embed', 'retrieve', 'handoff'
  actor:  string
  at:     string
  note?:  string
}

export interface HandOffManifest {
  sourceId:       string
  sourceHash:     string        // hash of the canonical source document
  chunkHash:      string        // merkle-style hash over chunk contents
  chunkIds:       string[]
  ingestionAudit: IngestionAudit
  chainOfCustody: CustodyEvent[]
  manifestHash:   string        // hash of the canonical manifest body
  keyId:          string
  signature:      string        // HMAC-SHA256(manifestHash) under keyId
  signedAt:       string
}

export interface HandOffVerifyResult {
  valid:   boolean
  reasons: string[]
}
