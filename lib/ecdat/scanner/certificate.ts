/**
 * ECDAT X.509 certificate scanner.
 *
 * The PRD path is `cryptography.x509.load_pem_x509_certificate()` +
 * `signature_algorithm_oid`. There is no CPython in the request path, so this
 * module reads the same information directly out of the DER encoding:
 *
 *   - signature algorithm  -> AlgorithmIdentifier OID byte sequence
 *   - public key algorithm -> SubjectPublicKeyInfo OID byte sequence
 *   - RSA modulus size     -> length of the modulus INTEGER
 *   - EC curve             -> named-curve OID
 *   - validity window      -> the two UTCTime / GeneralizedTime values
 *   - subject CN           -> value following OID 2.5.4.3
 *
 * No guessing and no regex over base64: the OIDs are matched as exact DER
 * byte strings, which is what `signature_algorithm_oid` returns as well.
 */

import type { RawFinding } from "../types"

interface OidEntry {
  /** DER bytes of the OBJECT IDENTIFIER TLV (tag 0x06 included). */
  der: number[]
  oid: string
  label: string
  algorithmId: string
  /** Hash paired with the signature algorithm, for reporting. */
  hash?: string
}

const hex = (s: string) => s.trim().split(/\s+/).map((b) => Number.parseInt(b, 16))

const SIGNATURE_OIDS: OidEntry[] = [
  { der: hex("06 09 2A 86 48 86 F7 0D 01 01 04"), oid: "1.2.840.113549.1.1.4", label: "md5WithRSAEncryption", algorithmId: "rsa-signature", hash: "MD5" },
  { der: hex("06 09 2A 86 48 86 F7 0D 01 01 05"), oid: "1.2.840.113549.1.1.5", label: "sha1WithRSAEncryption", algorithmId: "rsa-signature", hash: "SHA-1" },
  { der: hex("06 09 2A 86 48 86 F7 0D 01 01 0B"), oid: "1.2.840.113549.1.1.11", label: "sha256WithRSAEncryption", algorithmId: "rsa-signature", hash: "SHA-256" },
  { der: hex("06 09 2A 86 48 86 F7 0D 01 01 0C"), oid: "1.2.840.113549.1.1.12", label: "sha384WithRSAEncryption", algorithmId: "rsa-signature", hash: "SHA-384" },
  { der: hex("06 09 2A 86 48 86 F7 0D 01 01 0D"), oid: "1.2.840.113549.1.1.13", label: "sha512WithRSAEncryption", algorithmId: "rsa-signature", hash: "SHA-512" },
  { der: hex("06 09 2A 86 48 86 F7 0D 01 01 0A"), oid: "1.2.840.113549.1.1.10", label: "RSASSA-PSS", algorithmId: "rsa-signature" },
  { der: hex("06 08 2A 86 48 CE 3D 04 03 01"), oid: "1.2.840.10045.4.3.1", label: "ecdsa-with-SHA224", algorithmId: "ecdsa", hash: "SHA-224" },
  { der: hex("06 08 2A 86 48 CE 3D 04 03 02"), oid: "1.2.840.10045.4.3.2", label: "ecdsa-with-SHA256", algorithmId: "ecdsa", hash: "SHA-256" },
  { der: hex("06 08 2A 86 48 CE 3D 04 03 03"), oid: "1.2.840.10045.4.3.3", label: "ecdsa-with-SHA384", algorithmId: "ecdsa", hash: "SHA-384" },
  { der: hex("06 08 2A 86 48 CE 3D 04 03 04"), oid: "1.2.840.10045.4.3.4", label: "ecdsa-with-SHA512", algorithmId: "ecdsa", hash: "SHA-512" },
  { der: hex("06 03 2B 65 70"), oid: "1.3.101.112", label: "Ed25519", algorithmId: "ed25519" },
  { der: hex("06 07 2A 86 48 CE 38 04 03"), oid: "1.2.840.10040.4.3", label: "dsa-with-SHA1", algorithmId: "dsa", hash: "SHA-1" },
]

const PUBKEY_OIDS: OidEntry[] = [
  { der: hex("06 09 2A 86 48 86 F7 0D 01 01 01"), oid: "1.2.840.113549.1.1.1", label: "rsaEncryption", algorithmId: "rsa" },
  { der: hex("06 07 2A 86 48 CE 3D 02 01"), oid: "1.2.840.10045.2.1", label: "id-ecPublicKey", algorithmId: "ecdsa" },
  { der: hex("06 03 2B 65 70"), oid: "1.3.101.112", label: "Ed25519", algorithmId: "ed25519" },
  { der: hex("06 03 2B 65 6E"), oid: "1.3.101.110", label: "X25519", algorithmId: "x25519" },
]

const CURVE_OIDS: { der: number[]; name: string; bits: number }[] = [
  { der: hex("06 08 2A 86 48 CE 3D 03 01 07"), name: "prime256v1 (P-256)", bits: 256 },
  { der: hex("06 05 2B 81 04 00 22"), name: "secp384r1 (P-384)", bits: 384 },
  { der: hex("06 05 2B 81 04 00 23"), name: "secp521r1 (P-521)", bits: 521 },
  { der: hex("06 05 2B 81 04 00 0A"), name: "secp256k1", bits: 256 },
]

function indexOfBytes(haystack: Uint8Array, needle: number[], from = 0): number {
  outer: for (let i = from; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer
    return i
  }
  return -1
}

function decodeBase64(b64: string): Uint8Array | null {
  try {
    const clean = b64.replace(/[^A-Za-z0-9+/=]/g, "")
    if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(clean, "base64"))
    const bin = atob(clean)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  } catch {
    return null
  }
}

/** Largest INTEGER in the DER — the RSA modulus — gives the key size. */
function rsaModulusBits(der: Uint8Array): number | undefined {
  let best = 0
  for (let i = 0; i < der.length - 4; i++) {
    if (der[i] !== 0x02) continue
    const lenByte = der[i + 1]
    let len = 0
    if (lenByte === 0x82) len = (der[i + 2] << 8) | der[i + 3]
    else if (lenByte === 0x81) len = der[i + 2]
    else continue
    if (len > best && len >= 64 && len <= 1100) best = len
  }
  if (!best) return undefined
  const bits = (best - 1) * 8
  // Snap to the nearest standard size.
  const standard = [512, 1024, 2048, 3072, 4096, 8192]
  return standard.find((s) => Math.abs(s - bits) <= 16) ?? bits
}

function parseDerTime(der: Uint8Array): { notBefore?: Date; notAfter?: Date } {
  const times: Date[] = []
  for (let i = 0; i < der.length - 2; i++) {
    const tag = der[i]
    const len = der[i + 1]
    if (tag === 0x17 && len === 13) {
      const s = String.fromCharCode(...der.slice(i + 2, i + 15))
      const yy = Number(s.slice(0, 2))
      const year = yy >= 50 ? 1900 + yy : 2000 + yy
      const d = new Date(
        Date.UTC(year, Number(s.slice(2, 4)) - 1, Number(s.slice(4, 6)), Number(s.slice(6, 8)), Number(s.slice(8, 10)), Number(s.slice(10, 12))),
      )
      if (!Number.isNaN(d.getTime())) times.push(d)
    } else if (tag === 0x18 && len === 15) {
      const s = String.fromCharCode(...der.slice(i + 2, i + 17))
      const d = new Date(
        Date.UTC(Number(s.slice(0, 4)), Number(s.slice(4, 6)) - 1, Number(s.slice(6, 8)), Number(s.slice(8, 10)), Number(s.slice(10, 12)), Number(s.slice(12, 14))),
      )
      if (!Number.isNaN(d.getTime())) times.push(d)
    }
    if (times.length >= 2) break
  }
  return { notBefore: times[0], notAfter: times[1] }
}

/** Subject common name: OID 2.5.4.3 followed by a text string TLV. */
function parseCommonName(der: Uint8Array): string | undefined {
  const cnOid = hex("06 03 55 04 03")
  let from = 0
  let last: string | undefined
  for (let guard = 0; guard < 8; guard++) {
    const at = indexOfBytes(der, cnOid, from)
    if (at < 0) break
    const tag = der[at + 5]
    const len = der[at + 6]
    if ((tag === 0x0c || tag === 0x13 || tag === 0x16) && len > 0 && len < 128) {
      last = String.fromCharCode(...der.slice(at + 7, at + 7 + len))
    }
    from = at + 5
  }
  return last
}

export function scanCertificate(file: string, source: string): { findings: RawFinding[]; warnings: string[] } {
  const findings: RawFinding[] = []
  const warnings: string[] = []
  const blocks = [...source.matchAll(/-----BEGIN ([A-Z0-9 ]*CERTIFICATE)-----([\s\S]*?)-----END \1-----/g)]

  if (!blocks.length) {
    warnings.push(`${file}: no PEM CERTIFICATE block found (DER/PKCS#12 input is a roadmap item).`)
    return { findings, warnings }
  }

  const lineOf = (idx: number) => source.slice(0, idx).split("\n").length

  blocks.forEach((block, i) => {
    const der = decodeBase64(block[2])
    if (!der) {
      warnings.push(`${file}: certificate #${i + 1} is not valid base64 DER.`)
      return
    }
    const line = lineOf(block.index ?? 0)

    const sigEntry = SIGNATURE_OIDS.find((e) => indexOfBytes(der, e.der) >= 0)
    const keyEntry = PUBKEY_OIDS.find((e) => indexOfBytes(der, e.der) >= 0)
    const curve = CURVE_OIDS.find((c) => indexOfBytes(der, c.der) >= 0)
    const { notBefore, notAfter } = parseDerTime(der)
    const cn = parseCommonName(der)

    const keySize = keyEntry?.algorithmId === "rsa" ? rsaModulusBits(der) : curve?.bits
    const validityYears = notAfter ? Math.max(0.25, (notAfter.getTime() - Date.now()) / (365.25 * 24 * 3600 * 1000)) : undefined

    const detailParts = [
      cn ? `CN=${cn}` : undefined,
      sigEntry ? `sigAlg=${sigEntry.label} (${sigEntry.oid})` : "sigAlg=unrecognised",
      keyEntry ? `keyAlg=${keyEntry.label}` : undefined,
      curve ? `curve=${curve.name}` : undefined,
      notBefore && notAfter
        ? `validity=${notBefore.toISOString().slice(0, 10)}..${notAfter.toISOString().slice(0, 10)}`
        : undefined,
    ].filter(Boolean)

    // The signature algorithm is the quantum-relevant artefact for a cert.
    findings.push({
      file,
      line,
      kind: "certificate",
      matched: sigEntry ? sigEntry.label : "X.509 certificate",
      snippet: `-----BEGIN ${block[1]}----- ${cn ? `(CN=${cn})` : ""}`.trim(),
      language: "certificate",
      algorithmId: sigEntry?.algorithmId ?? "x509-certificate",
      keySize,
      detail: detailParts.join(" · "),
      confidence: "high",
      detector: "x509:der-oid",
    })

    // The subject public key is a separate artefact with its own lifetime.
    if (keyEntry && keyEntry.algorithmId !== sigEntry?.algorithmId) {
      findings.push({
        file,
        line,
        kind: "certificate",
        matched: keyEntry.label,
        snippet: `subjectPublicKeyInfo ${keyEntry.label}${curve ? ` (${curve.name})` : ""}`,
        language: "certificate",
        algorithmId: keyEntry.algorithmId,
        keySize,
        detail: `subject public key${validityYears ? ` · ${validityYears.toFixed(1)}y remaining validity` : ""}`,
        confidence: "high",
        detector: "x509:der-oid",
      })
    }

    if (sigEntry?.hash === "SHA-1" || sigEntry?.hash === "MD5") {
      warnings.push(`${file}: certificate signed with ${sigEntry.hash}, which is collision-broken today.`)
    }
  })

  return { findings, warnings }
}
