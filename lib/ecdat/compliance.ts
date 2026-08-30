/**
 * Compliance posture scoring against published PQC mandates.
 *
 * Every control below cites a real, public deadline. ECDAT scores the scanned
 * codebase against them so the output answers the question an auditor actually
 * asks — "are you on track for the 2030/2035 deprecation?" — rather than only
 * listing algorithms.
 *
 * Sources:
 *  - NIST IR 8547 (initial public draft, Nov 2024): RSA/ECDSA/ECDH/DH
 *    deprecated after 2030, disallowed after 2035.
 *  - NSA CNSA 2.0 (updated Apr 2024): PQC exclusive for NSS by 2033; software
 *    and firmware signing transition begins 2025 and is exclusive by 2030.
 *  - NIST SP 800-131A Rev. 2: SHA-1 disallowed for digital signatures,
 *    Triple-DES disallowed after 2023, 112-bit minimum symmetric strength.
 *  - FIPS 203/204/205 (Aug 2024): ML-KEM, ML-DSA, SLH-DSA approved.
 */

import type { CryptoAsset } from "./types"

export type ControlStatus = "pass" | "warn" | "fail" | "not-applicable"

export interface ComplianceControl {
  id: string
  framework: "NIST IR 8547" | "NSA CNSA 2.0" | "NIST SP 800-131A" | "FIPS 203/204/205"
  title: string
  requirement: string
  deadline: string
  status: ControlStatus
  /** Assets that violate (or satisfy) the control. */
  offenders: { name: string; location: string }[]
  detail: string
  /** Weight in the overall posture score. */
  weight: number
}

function offendersOf(assets: CryptoAsset[], predicate: (a: CryptoAsset) => boolean) {
  return assets
    .filter(predicate)
    .slice(0, 25)
    .map((a) => ({ name: a.name, location: a.location }))
}

function statusFrom(count: number, warnOnly = false): ControlStatus {
  if (count === 0) return "pass"
  return warnOnly ? "warn" : "fail"
}

export function evaluateCompliance(assets: CryptoAsset[]): ComplianceControl[] {
  const has = (predicate: (a: CryptoAsset) => boolean) => assets.filter(predicate)

  const rsaEcc = has((a) => a.quantumVulnerable && (a.family === "RSA" || a.family === "ECC" || a.family === "DH" || a.family === "DSA"))
  const sha1 = has((a) => a.family === "SHA1")
  const md5 = has((a) => a.family === "MD5")
  const weakSym = has((a) => (a.family === "DES" || a.family === "3DES" || a.family === "RC4" || a.family === "BLOWFISH"))
  const smallAes = has((a) => a.family === "AES" && (a.keySize ?? 128) < 256)
  const legacyTls = has((a) => a.family === "TLS" && /1\.[01]|SSL/i.test(a.name))
  const pqc = has((a) => a.family === "PQC")
  const signing = has((a) => a.primitive === "signature" && a.quantumVulnerable)
  const keyEstablishment = has((a) => (a.primitive === "key-agreement" || a.primitive === "public-key-encryption") && a.quantumVulnerable)
  const weakRng = has((a) => a.primitive === "drbg")
  const certs = has((a) => a.type === "certificate" && a.quantumVulnerable)

  const controls: ComplianceControl[] = [
    {
      id: "IR8547-1",
      framework: "NIST IR 8547",
      title: "RSA / ECC / DH deprecated after 2030",
      requirement: "112-bit classical public-key algorithms are deprecated after 2030 and disallowed after 2035.",
      deadline: "2030 deprecated · 2035 disallowed",
      status: statusFrom(rsaEcc.length),
      offenders: offendersOf(assets, (a) => rsaEcc.includes(a)),
      detail:
        rsaEcc.length === 0
          ? "No classical public-key cryptography detected in scanned scope."
          : `${rsaEcc.length} asset${rsaEcc.length === 1 ? "" : "s"} rely on RSA/ECC/DH/DSA and must be migrated before the 2035 disallow date.`,
      weight: 3,
    },
    {
      id: "CNSA2-KEM",
      framework: "NSA CNSA 2.0",
      title: "Key establishment must be ML-KEM",
      requirement: "CNSA 2.0 requires ML-KEM-1024 for key establishment in national-security systems.",
      deadline: "Transition from 2025 · exclusive by 2033",
      status: statusFrom(keyEstablishment.length),
      offenders: offendersOf(assets, (a) => keyEstablishment.includes(a)),
      detail:
        keyEstablishment.length === 0
          ? "No quantum-vulnerable key establishment detected."
          : `${keyEstablishment.length} key-establishment asset${keyEstablishment.length === 1 ? "" : "s"} exposed to harvest-now-decrypt-later. Hybrid X25519MLKEM768 closes this immediately.`,
      weight: 3,
    },
    {
      id: "CNSA2-SIG",
      framework: "NSA CNSA 2.0",
      title: "Software & firmware signing must be PQC",
      requirement: "ML-DSA-87 (or LMS/XMSS for firmware) required; classical signing exclusive-out by 2030.",
      deadline: "2025 begin · 2030 exclusive",
      status: statusFrom(signing.length),
      offenders: offendersOf(assets, (a) => signing.includes(a)),
      detail:
        signing.length === 0
          ? "No quantum-vulnerable signature algorithms detected."
          : `${signing.length} signature asset${signing.length === 1 ? "" : "s"} still classical. Signing keys are long-lived, so this is the earliest CNSA 2.0 deadline.`,
      weight: 3,
    },
    {
      id: "CNSA2-CERT",
      framework: "NSA CNSA 2.0",
      title: "X.509 certificates on PQC algorithms",
      requirement: "Certificate chains must be reissued on approved PQC signature algorithms.",
      deadline: "2033",
      status: certs.length === 0 ? "not-applicable" : "fail",
      offenders: offendersOf(assets, (a) => certs.includes(a)),
      detail:
        certs.length === 0
          ? "No X.509 certificates were found in the scanned scope."
          : `${certs.length} certificate${certs.length === 1 ? "" : "s"} signed with quantum-vulnerable algorithms; plan reissue with a PQC-capable CA.`,
      weight: 2,
    },
    {
      id: "131A-SHA1",
      framework: "NIST SP 800-131A",
      title: "SHA-1 disallowed for digital signatures",
      requirement: "SHA-1 is disallowed for signature generation and is being removed entirely by 2030.",
      deadline: "Already disallowed",
      status: statusFrom(sha1.length),
      offenders: offendersOf(assets, (a) => sha1.includes(a)),
      detail: sha1.length === 0 ? "No SHA-1 usage detected." : `${sha1.length} SHA-1 usage(s) found — collision attacks are practical today.`,
      weight: 2,
    },
    {
      id: "131A-MD5",
      framework: "NIST SP 800-131A",
      title: "MD5 not approved for any security function",
      requirement: "MD5 must not be used for integrity, signatures, or password storage.",
      deadline: "Already disallowed",
      status: statusFrom(md5.length),
      offenders: offendersOf(assets, (a) => md5.includes(a)),
      detail: md5.length === 0 ? "No MD5 usage detected." : `${md5.length} MD5 usage(s) found — trivially collidable; remediate independently of PQC.`,
      weight: 2,
    },
    {
      id: "131A-SYM",
      framework: "NIST SP 800-131A",
      title: "Legacy symmetric ciphers disallowed",
      requirement: "DES, Triple-DES (after 2023), RC4 and Blowfish are disallowed; 112-bit minimum strength.",
      deadline: "Already disallowed",
      status: statusFrom(weakSym.length),
      offenders: offendersOf(assets, (a) => weakSym.includes(a)),
      detail: weakSym.length === 0 ? "No disallowed symmetric ciphers detected." : `${weakSym.length} legacy cipher usage(s) found.`,
      weight: 2,
    },
    {
      id: "CNSA2-AES",
      framework: "NSA CNSA 2.0",
      title: "Symmetric encryption at AES-256",
      requirement: "CNSA 2.0 mandates AES-256 to preserve a 128-bit post-quantum margin against Grover.",
      deadline: "2030 exclusive",
      status: statusFrom(smallAes.length, true),
      offenders: offendersOf(assets, (a) => smallAes.includes(a)),
      detail:
        smallAes.length === 0
          ? "No sub-256-bit AES usage detected."
          : `${smallAes.length} AES usage(s) below 256-bit. Not broken by Shor — raise the key size rather than replacing the algorithm.`,
      weight: 1,
    },
    {
      id: "TLS-MIN",
      framework: "NIST SP 800-131A",
      title: "TLS 1.2+ with PQ hybrid key exchange",
      requirement: "TLS 1.0/1.1 and SSL are prohibited; PQ hybrid groups required to stop traffic harvesting.",
      deadline: "Already prohibited",
      status: statusFrom(legacyTls.length),
      offenders: offendersOf(assets, (a) => legacyTls.includes(a)),
      detail: legacyTls.length === 0 ? "No prohibited TLS/SSL versions detected in configuration." : `${legacyTls.length} legacy TLS/SSL configuration(s) found.`,
      weight: 2,
    },
    {
      id: "90A-RNG",
      framework: "NIST SP 800-131A",
      title: "Cryptographic keys from an approved DRBG",
      requirement: "Keys and nonces must come from an SP 800-90A DRBG, never a statistical PRNG.",
      deadline: "Continuous",
      status: statusFrom(weakRng.length),
      offenders: offendersOf(assets, (a) => weakRng.includes(a)),
      detail: weakRng.length === 0 ? "No non-cryptographic RNG usage detected in crypto context." : `${weakRng.length} non-cryptographic RNG usage(s) — predictable keys defeat any algorithm.`,
      weight: 2,
    },
    {
      id: "FIPS-ADOPT",
      framework: "FIPS 203/204/205",
      title: "Approved PQC algorithms in use",
      requirement: "Evidence of ML-KEM, ML-DSA, SLH-DSA, LMS or XMSS adoption in the codebase.",
      deadline: "Available since Aug 2024",
      status: pqc.length > 0 ? "pass" : "warn",
      offenders: offendersOf(assets, (a) => pqc.includes(a)),
      detail:
        pqc.length > 0
          ? `${pqc.length} approved PQC usage(s) detected — migration is underway.`
          : "No FIPS 203/204/205 algorithm usage detected. Even a pilot integration de-risks the eventual cut-over.",
      weight: 1,
    },
  ]

  return controls
}

export interface CompliancePosture {
  score: number
  grade: "A" | "B" | "C" | "D" | "F"
  controls: ComplianceControl[]
  passed: number
  warned: number
  failed: number
  notApplicable: number
  /** Years remaining against the nearest hard deadline. */
  headline: string
}

export function compliancePosture(assets: CryptoAsset[]): CompliancePosture {
  const controls = evaluateCompliance(assets)
  const scored = controls.filter((c) => c.status !== "not-applicable")
  const totalWeight = scored.reduce((s, c) => s + c.weight, 0) || 1
  const earned = scored.reduce((s, c) => s + (c.status === "pass" ? c.weight : c.status === "warn" ? c.weight * 0.5 : 0), 0)
  const score = Math.round((earned / totalWeight) * 100)

  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 55 ? "C" : score >= 35 ? "D" : "F"
  const failed = controls.filter((c) => c.status === "fail").length
  const currentYear = new Date().getFullYear()

  return {
    score,
    grade,
    controls,
    passed: controls.filter((c) => c.status === "pass").length,
    warned: controls.filter((c) => c.status === "warn").length,
    failed,
    notApplicable: controls.filter((c) => c.status === "not-applicable").length,
    headline:
      failed === 0
        ? "No failing controls in scanned scope."
        : `${failed} failing control${failed === 1 ? "" : "s"} · ${2030 - currentYear} years to the NIST IR 8547 deprecation date, ${2035 - currentYear} to disallow.`,
  }
}
