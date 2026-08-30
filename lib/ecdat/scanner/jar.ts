/**
 * ECDAT JAR metadata detector (F9) — the minimum viable slice of binary scanning.
 *
 * Scope, deliberately narrow and stated in the UI on every finding it produces:
 * this reads the *ZIP directory* of a `.jar` — entry names and the manifest text
 * — and maps known crypto package paths onto algorithm ids. It does not
 * decompile bytecode, does not resolve call sites, and does not follow the
 * shaded/relocated packages some fat JARs use. Native binaries (`.exe`, `.so`,
 * `.dll`) remain out of scope.
 *
 * Entry names live uncompressed in every ZIP local file header, so no inflate
 * implementation is needed: the JAR is read as a byte-preserving latin1 string
 * and the headers are walked directly.
 */

import { DEPENDENCY_SIGNATURES, getAlgorithm, keySizeFromString, resolveAlgorithmString } from "../signatures"
import type { RawFinding } from "../types"

const LOCAL_HEADER = String.fromCharCode(0x50, 0x4b, 0x03, 0x04)

/** Class-path prefixes that identify a cryptographic provider inside a JAR. */
const PACKAGE_MAP: { prefix: string; algorithmId: string; library: string }[] = [
  { prefix: "org/bouncycastle/pqc/", algorithmId: "ml-kem", library: "BouncyCastle PQC" },
  { prefix: "org/bouncycastle/", algorithmId: "crypto-library", library: "BouncyCastle" },
  { prefix: "javax/crypto/", algorithmId: "crypto-library", library: "javax.crypto" },
  { prefix: "java/security/", algorithmId: "crypto-library", library: "java.security" },
  { prefix: "javax/net/ssl/", algorithmId: "tls1.2", library: "javax.net.ssl" },
  { prefix: "sun/security/pkcs11/", algorithmId: "hsm", library: "SunPKCS11" },
  { prefix: "com/nimbusds/jose/", algorithmId: "jwt", library: "Nimbus JOSE+JWT" },
  { prefix: "io/jsonwebtoken/", algorithmId: "jwt", library: "jjwt" },
  { prefix: "com/auth0/jwt/", algorithmId: "jwt", library: "java-jwt" },
  { prefix: "net/i2p/crypto/eddsa/", algorithmId: "ed25519", library: "ed25519-java" },
  { prefix: "org/apache/commons/codec/digest/", algorithmId: "crypto-library", library: "commons-codec" },
  { prefix: "org/openquantumsafe/", algorithmId: "ml-kem", library: "liboqs-java" },
  { prefix: "com/amazonaws/cloudhsm/", algorithmId: "hsm", library: "AWS CloudHSM" },
  { prefix: "com/amazonaws/services/kms/", algorithmId: "cloud-kms", library: "AWS KMS SDK" },
  { prefix: "software/amazon/awssdk/services/kms/", algorithmId: "cloud-kms", library: "AWS KMS SDK v2" },
  { prefix: "com/azure/security/keyvault/", algorithmId: "cloud-kms", library: "Azure Key Vault SDK" },
  { prefix: "com/google/cloud/kms/", algorithmId: "cloud-kms", library: "Google Cloud KMS SDK" },
  { prefix: "com/safenetinc/luna/", algorithmId: "hsm", library: "Thales Luna SDK" },
]

/** Class *names* that identify a specific primitive, e.g. `AESGCMEncryption`. */
const CLASS_NAME_HINTS = /(AESGCM|AESCBC|AESECB|AESCTR|TripleDES|DESede|Blowfish|RC4|MD5|SHA1|SHA256|RSAEncryption|RSASignature|ECDSA|Ed25519|X25519|Kyber|MLKEM|Dilithium|MLDSA)/

export function isJarPath(path: string): boolean {
  return /\.(jar|war|ear)$/i.test(path)
}

/** Walk ZIP local file headers and return the entry names. */
export function jarEntryNames(binary: string, limit = 20000): string[] {
  const names: string[] = []
  let index = binary.indexOf(LOCAL_HEADER)
  while (index !== -1 && names.length < limit) {
    const nameLength = binary.charCodeAt(index + 26) | (binary.charCodeAt(index + 27) << 8)
    const extraLength = binary.charCodeAt(index + 28) | (binary.charCodeAt(index + 29) << 8)
    if (nameLength > 0 && nameLength < 1024) {
      names.push(binary.slice(index + 30, index + 30 + nameLength))
    }
    const next = binary.indexOf(LOCAL_HEADER, index + 30 + nameLength + extraLength)
    index = next === -1 ? binary.indexOf(LOCAL_HEADER, index + 4) : next
    if (index !== -1 && index <= 0) break
  }
  return names
}

export function scanJar(file: string, binary: string): { findings: RawFinding[]; warnings: string[] } {
  const findings: RawFinding[] = []
  const warnings: string[] = []
  const base = file.split("/").pop() ?? file
  const names = jarEntryNames(binary)

  if (!names.length) {
    warnings.push(
      `${file}: could not read the ZIP directory (truncated or text-decoded upload) — JAR metadata inspection skipped.`,
    )
    return { findings, warnings }
  }

  const push = (algorithmId: string, detailBase: string, evidenceName: string, keySize?: number, mode?: string) => {
    const spec = getAlgorithm(algorithmId)
    findings.push({
      file,
      line: 1,
      kind: "binary",
      matched: evidenceName.slice(0, 160),
      snippet: `${base} » ${evidenceName}`,
      language: "binary",
      algorithmId,
      keySize: keySize ?? spec.defaultKeySize,
      mode,
      detail: `${detailBase} — JAR metadata inspection, bytecode not decompiled`,
      confidence: "medium",
      detector: "binary:jar/entries",
      scopeNote: "Detected via binary metadata inspection",
    })
  }

  // ------------------------------------------------- provider package presence
  const packageHits = new Map<string, { library: string; count: number; example: string }>()
  for (const name of names) {
    const hit = PACKAGE_MAP.find((p) => name.startsWith(p.prefix))
    if (!hit) continue
    const entry = packageHits.get(hit.algorithmId + hit.prefix)
    if (entry) {
      entry.count++
      continue
    }
    packageHits.set(hit.algorithmId + hit.prefix, { library: hit.library, count: 1, example: name })
  }
  for (const [key, value] of packageHits) {
    const hit = PACKAGE_MAP.find((p) => key === p.algorithmId + p.prefix)
    if (!hit) continue
    push(hit.algorithmId, `${value.library} classes present (${value.count} entries)`, value.example)
  }

  // ------------------------------------------------------- class-name hints
  const nameHits = new Set<string>()
  for (const name of names) {
    if (!name.endsWith(".class")) continue
    const cls = name.split("/").pop() ?? name
    const hint = cls.match(CLASS_NAME_HINTS)
    if (!hint) continue
    const algorithmId = resolveAlgorithmString(hint[1])
    if (!algorithmId || nameHits.has(algorithmId + hint[1])) continue
    nameHits.add(algorithmId + hint[1])
    const mode = hint[1].match(/(GCM|CBC|ECB|CTR)$/)?.[1]
    push(algorithmId, `class name \`${cls}\` implies ${hint[1]}`, name, keySizeFromString(cls), mode)
  }

  // ------------------------------------------------ the JAR's own coordinates
  for (const dep of DEPENDENCY_SIGNATURES) {
    if (!dep.token.test(base)) continue
    const spec = getAlgorithm(dep.algorithmId)
    findings.push({
      file,
      line: 1,
      kind: "binary",
      matched: base,
      snippet: `packaged dependency: ${base}`,
      language: "binary",
      algorithmId: dep.algorithmId,
      keySize: spec.defaultKeySize,
      detail: `${dep.library} shipped as a JAR — JAR metadata inspection, bytecode not decompiled`,
      confidence: "medium",
      detector: "binary:jar/filename",
      scopeNote: "Detected via binary metadata inspection",
    })
    break
  }

  if (names.some((n) => n === "META-INF/MANIFEST.MF")) {
    const manifest = binary.match(/(?:Implementation-Title|Bundle-Name|Automatic-Module-Name):\s*([^\r\n]+)/)
    if (manifest) {
      warnings.push(`${file}: JAR manifest declares "${manifest[1].trim()}" (recorded as evidence detail only).`)
    }
  }

  if (!findings.length) {
    warnings.push(`${file}: ${names.length} entries inspected, no known cryptographic package paths found.`)
  }

  return { findings, warnings }
}
