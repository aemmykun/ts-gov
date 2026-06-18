import { HandOffManifest, IngestionAudit, CustodyEvent } from './types'
import { canonicalJson, sha256, hashContents, signManifest, SigningKey } from './HandOffSigner'

export interface HandOffInput {
  sourceId:       string
  sourceContent:  string       // canonical source document text
  chunkIds:       string[]
  chunkContents:  string[]     // aligned with chunkIds, order-significant
  ingestionAudit: IngestionAudit
  chainOfCustody: CustodyEvent[]
}

export class HandOffBuilder {
  build(input: HandOffInput, key: SigningKey): HandOffManifest {
    if (input.chunkIds.length !== input.chunkContents.length) {
      throw new Error('HANDOFF: chunkIds and chunkContents length mismatch')
    }

    const sourceHash = sha256(input.sourceContent)
    const chunkHash  = hashContents(input.chunkContents)
    const signedAt   = new Date().toISOString()

    // Body that is hashed; signature is taken over the manifestHash.
    const body = {
      sourceId:       input.sourceId,
      sourceHash,
      chunkHash,
      chunkIds:       input.chunkIds,
      ingestionAudit: input.ingestionAudit,
      chainOfCustody: input.chainOfCustody,
    }
    const manifestHash = sha256(canonicalJson(body))
    const signature    = signManifest(manifestHash, key)

    return {
      ...body,
      manifestHash,
      keyId:     key.keyId,
      signature,
      signedAt,
    }
  }
}
