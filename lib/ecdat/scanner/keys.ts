/**
 * ECDAT standalone key-material detector (F1).
 *
 * The problem statement names *keys* alongside algorithms and certificates as a
 * thing to catalogue. Before this detector, key size was only ever a property of
 * something else — a loose `service.key`, a `truststore.jks`, or an AES key
 * pasted into a config file produced no inventory entry at all.
 *
 * Two evidence classes:
 *   - file-level: the extension itself is the artefact (`.key`, `.p12`, `.jks`)
 *   - literal-level: a key-shaped string assigned in source or config
 *
 * Nothing here decrypts, parses or validates the key. A keystore is reported as
 * a container to inspect, not as a resolved list of the keys inside it.
 */

import {
  KEY_FILE_TYPES,
  KEY_PLACEHOLDERS,
  KEY_SIGNATURES,
  getAlgorithm,
  keySizeFromString,
} from "../signatures"
import type { RawFinding } from "../types"
import { lineAt, lineIndex } from "./regex-langs"

export const KEY_EXTENSIONS = new Set(Object.keys(KEY_FILE_TYPES))

export function isKeyFile(path: string): boolean {
  const base = (path.split("/").pop() ?? path).toLowerCase()
  const dot = base.lastIndexOf(".")
  if (dot <= 0) return false
  return KEY_EXTENSIONS.has(base.slice(dot))
}

/** Cheap shape test so `apiKey = "getUserProfile"` is not reported as a key. */
function looksLikeKeyMaterial(value: string): boolean {
  if (KEY_PLACEHOLDERS.test(value)) return false
  if (value.length < 16) return false
  const hasDigit = /\d/.test(value)
  const hasUpper = /[A-Z]/.test(value)
  const hasLower = /[a-z]/.test(value)
  const hasSymbol = /[+/=_-]/.test(value)
  const isHex = /^[0-9a-fA-F]+$/.test(value) && value.length >= 32
  const classes = [hasDigit, hasUpper, hasLower, hasSymbol].filter(Boolean).length
  // Base64/hex key material mixes character classes; an English identifier or a
  // sentence-like default value does not.
  return isHex || classes >= 3
}

/**
 * Key-shaped literals inside a text file. Safe to run over any language: the
 * caller passes comment-stripped source so a commented-out sample key is not
 * reported.
 */
export function scanKeyLiterals(file: string, source: string, cleaned = source): RawFinding[] {
  const findings: RawFinding[] = []
  const offsets = lineIndex(source)
  const lines = source.split("\n")
  const seen = new Set<string>()

  for (const sig of KEY_SIGNATURES) {
    const re = new RegExp(sig.pattern.source, sig.pattern.flags.includes("g") ? sig.pattern.flags : `${sig.pattern.flags}g`)
    // PEM blocks survive comment stripping only in the raw text (they contain
    // `/` characters that the string-state machine does not treat specially),
    // so literals are matched against the cleaned text and PEM against raw.
    const haystack = sig.valueGroup === undefined ? source : cleaned
    let m: RegExpExecArray | null
    while ((m = re.exec(haystack)) !== null) {
      if (!m[0]) {
        re.lastIndex++
        continue
      }
      if (sig.valueGroup !== undefined) {
        const value = m[sig.valueGroup]
        if (!value || !looksLikeKeyMaterial(value)) continue
      }
      const line = lineAt(offsets, m.index)
      const dedupe = `${sig.id}:${line}`
      if (seen.has(dedupe)) continue
      seen.add(dedupe)

      const spec = getAlgorithm(sig.algorithmId)
      const literal = sig.valueGroup !== undefined ? m[sig.valueGroup] : undefined
      findings.push({
        file,
        line,
        kind: sig.valueGroup !== undefined ? "string-literal" : "key-file",
        matched: m[0].trim().slice(0, 80),
        // Never echo the secret itself into the report.
        snippet: literal
          ? (lines[line - 1] ?? "").trim().replace(literal, `«${literal.length} chars redacted»`).slice(0, 220)
          : (lines[line - 1] ?? "").trim().slice(0, 220),
        language: "unknown",
        algorithmId: sig.algorithmId,
        keySize: literal ? inferLiteralKeyBits(literal) : spec.defaultKeySize,
        detail: sig.detail,
        confidence: sig.valueGroup === undefined ? "high" : "medium",
        detector: `key:${sig.id}`,
        assetType: "key",
        label: sig.label,
      })
    }
  }

  return findings
}

/** Bits implied by a literal's encoding — hex is 4 bits/char, base64 6. */
function inferLiteralKeyBits(value: string): number | undefined {
  if (/^[0-9a-fA-F]+$/.test(value) && value.length % 2 === 0) {
    const bits = value.length * 4
    return bits >= 64 && bits <= 8192 ? bits : undefined
  }
  const bits = Math.floor((value.replace(/=+$/, "").length * 6) / 8) * 8
  return bits >= 64 && bits <= 8192 ? bits : undefined
}

/**
 * A key/keystore file. The file's existence is the finding; the content is only
 * used to refine the label (an `.key` holding an EC key says so in its header).
 */
export function scanKeyFile(file: string, content: string): { findings: RawFinding[]; warnings: string[] } {
  const base = (file.split("/").pop() ?? file).toLowerCase()
  const ext = base.slice(base.lastIndexOf("."))
  const type = KEY_FILE_TYPES[ext] ?? { algorithmId: "key-material", label: "Key material", detail: "key file" }
  const warnings: string[] = []

  let label = type.label
  let detail = type.detail
  let keySize: number | undefined

  const header = content.slice(0, 4096)
  const pem = header.match(/-----BEGIN (RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP)? ?(PRIVATE|PUBLIC) KEY-----/)
  if (pem) {
    const kind = pem[2] === "PRIVATE" ? "private key" : "public key"
    const flavour = pem[1] ? `${pem[1]} ` : ""
    label = `${flavour}${kind}`.replace(/^\w/, (c) => c.toUpperCase())
    detail = `PEM ${flavour}${kind} in ${ext} file`
  } else if (/^\s*\x30\x82/.test(header) || /(?:\xfe\xed\xfe\xed|\xce\xce\xce\xce)/.test(header)) {
    detail = `${type.detail} (binary container — contents not parsed)`
  } else if (ext === ".jks" || ext === ".keystore" || ext === ".p12" || ext === ".pfx" || ext === ".bks") {
    detail = `${type.detail} (contents not parsed — inventory the contained keys manually)`
  }

  const curve = header.match(/\b(prime256v1|secp256r1|secp384r1|secp521r1|secp256k1|Ed25519|X25519)\b/i)
  if (curve) detail += ` · curve ${curve[1]}`
  keySize = keySizeFromString(base) ?? keySizeFromString(curve?.[1] ?? "")

  const findings: RawFinding[] = [
    {
      file,
      line: 1,
      kind: "key-file",
      matched: base,
      snippet: pem ? pem[0] : `${type.label}: ${base}`,
      language: "key",
      algorithmId: type.algorithmId,
      keySize,
      detail,
      confidence: "high",
      detector: `key:file${ext}`,
      assetType: "key",
      label,
    },
  ]

  // Loose key files are the classic "committed by accident" artefact; say so
  // once per file rather than per finding.
  if (pem?.[2] === "PRIVATE" || ext === ".key" || ext === ".p8" || ext === ".pk8") {
    warnings.push(`${file}: private key material found in the scanned tree — confirm this is intentional.`)
  }

  return { findings, warnings }
}
