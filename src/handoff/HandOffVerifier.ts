import { HandOffManifest, HandOffVerifyResult } from './types'
import { canonicalJson, sha256, hashContents, signManifest, safeEqual, SigningKey } from './HandOffSigner'

export interface HandOffEvidence {
  sourceContent?: string    // when present, source hash is re-derived & checked
  chunkContents?: string[]  // when present, chunk hash is re-derived & checked
}

export class HandOffVerifier {
  // Verifies signature + manifest hash, and (when raw evidence is supplied)
  // re-derives source/chunk hashes to prove the bytes match the manifest.
  verify(
    manifest: HandOffManifest,
    key: SigningKey,
    evidence: HandOffEvidence = {},
  ): HandOffVerifyResult {
    const reasons: string[] = []

    if (manifest.keyId !== key.keyId) {
      reasons.push(`Unknown signing key '${manifest.keyId}'`)
    }

    const body = {
      sourceId:       manifest.sourceId,
      sourceHash:     manifest.sourceHash,
      chunkHash:      manifest.chunkHash,
      chunkIds:       manifest.chunkIds,
      ingestionAudit: manifest.ingestionAudit,
      chainOfCustody: manifest.chainOfCustody,
    }

    const recomputedManifestHash = sha256(canonicalJson(body))
    if (recomputedManifestHash !== manifest.manifestHash) {
      reasons.push('Manifest hash mismatch (manifest body altered)')
    }

    const expectedSig = signManifest(manifest.manifestHash, key)
    if (!safeEqual(expectedSig, manifest.signature)) {
      reasons.push('Manifest signature invalid')
    }

    if (evidence.sourceContent !== undefined) {
      if (sha256(evidence.sourceContent) !== manifest.sourceHash) {
        reasons.push('Source content does not match sourceHash')
      }
    }

    if (evidence.chunkContents !== undefined) {
      if (hashContents(evidence.chunkContents) !== manifest.chunkHash) {
        reasons.push('Chunk content does not match chunkHash')
      }
    }

    if (!manifest.chainOfCustody || manifest.chainOfCustody.length === 0) {
      reasons.push('Chain-of-custody is empty')
    }

    return { valid: reasons.length === 0, reasons }
  }
}
