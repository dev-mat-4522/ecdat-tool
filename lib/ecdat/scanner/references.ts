/**
 * ECDAT reference detector — hardware modules (F3) and cloud KMS (F4).
 *
 * Scope, stated up front because it is the whole point of the module:
 * this detector reports that a codebase *integrates with* an HSM or a cloud key
 * management service. It never opens a PKCS#11 session, never calls a cloud API
 * and never enumerates the keys held in either. Every finding it produces
 * carries a scope caption so a reader cannot mistake it for a live inventory.
 *
 * Same signature-table approach as the language detectors, so adding a vendor is
 * a data change in `signatures.ts`.
 */

import { CLOUD_SIGNATURES, HSM_SIGNATURES, getAlgorithm, type ReferenceSignature } from "../signatures"
import type { Language, RawFinding } from "../types"
import { lineAt, lineIndex, stripComments } from "./regex-langs"

const ALL_REFERENCES: ReferenceSignature[] = [...HSM_SIGNATURES, ...CLOUD_SIGNATURES]

/**
 * Runs over any text file ECDAT already opened — source, config, IaC or
 * manifest. Comments are stripped first so a "we should move to CloudHSM" note
 * never becomes an inventory entry.
 */
export function scanReferences(file: string, source: string, language: Language): RawFinding[] {
  const findings: RawFinding[] = []
  const cleaned = stripComments(source, language)
  const offsets = lineIndex(source)
  const lines = source.split("\n")
  // One artefact per signature per file: a KMS client constructed in twelve
  // places is one integration, and the occurrence count carries the volume.
  const seen = new Set<string>()

  for (const sig of ALL_REFERENCES) {
    const re = new RegExp(sig.pattern.source, sig.pattern.flags.includes("g") ? sig.pattern.flags : `${sig.pattern.flags}g`)
    let m: RegExpExecArray | null
    while ((m = re.exec(cleaned)) !== null) {
      if (!m[0]) {
        re.lastIndex++
        continue
      }
      const line = lineAt(offsets, m.index)
      const key = `${sig.id}:${line}`
      if (seen.has(key)) continue
      seen.add(key)

      const spec = getAlgorithm(sig.algorithmId)
      findings.push({
        file,
        line,
        kind: sig.kind === "config" ? "config" : sig.kind === "call" ? "call" : "import",
        matched: m[0].trim().slice(0, 160),
        snippet: (lines[line - 1] ?? "").trim().slice(0, 220),
        language,
        algorithmId: sig.algorithmId,
        keySize: spec.defaultKeySize,
        detail: `${sig.library} — reference only, no live query performed`,
        confidence: "medium",
        detector: `reference:${sig.id}`,
        assetType: sig.assetType,
        label: sig.label,
      })
    }
  }

  return findings
}
