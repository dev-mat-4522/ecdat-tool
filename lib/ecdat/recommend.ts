/**
 * ECDAT recommendation engine — Step 5 of the pipeline.
 *
 * Pure lookup over the NIST PQC standards finalised in August 2024:
 *   FIPS 203  ML-KEM   (Kyber)     — key establishment
 *   FIPS 204  ML-DSA   (Dilithium) — general-purpose signatures
 *   FIPS 205  SLH-DSA  (SPHINCS+)  — conservative, hash-based signatures
 * Plus SP 800-131A guidance for symmetric/hash primitives, which are only
 * weakened by Grover and therefore resized rather than replaced.
 *
 * F8 — the choice is then weighted by cost of deployment, not just cryptographic
 * strength: every recommendation carries a one-line performance consequence, and
 * an asset that is both high-criticality and external-facing is steered to the
 * hybrid suite instead of pure PQC (a PQC-only handshake on a public edge bets
 * the whole connection on a young implementation).
 */

import { getAlgorithm } from "./signatures"
import type { CryptoAsset, Recommendation } from "./types"

function kemParamSet(keySize?: number): string {
  if (!keySize) return "ML-KEM-768"
  if (keySize >= 4096 || keySize >= 384) return "ML-KEM-1024"
  if (keySize >= 2048 || keySize >= 256) return "ML-KEM-768"
  return "ML-KEM-512"
}

function dsaParamSet(keySize?: number): string {
  if (!keySize) return "ML-DSA-65"
  if (keySize >= 4096 || keySize >= 384) return "ML-DSA-87"
  if (keySize >= 2048 || keySize >= 256) return "ML-DSA-65"
  return "ML-DSA-44"
}

/**
 * F8 — static latency/size characteristic for whatever the target happens to be.
 * PQC families read their note from the signature DB so the number lives in one
 * place; the classical targets are described inline because they have no spec
 * entry of their own to hang a note on.
 */
function performanceNoteFor(target: string): string | undefined {
  if (/ML-KEM|MLKEM|sntrup/i.test(target)) return getAlgorithm("ml-kem").latencyNote
  if (/ML-DSA/i.test(target)) return getAlgorithm("ml-dsa").latencyNote
  if (/SLH-DSA/i.test(target)) return getAlgorithm("slh-dsa").latencyNote
  if (/AES-256/i.test(target)) {
    return "AES-256 costs no extra bytes on the wire and runs on the same AES-NI path as AES-128 — ~5% more CPU per block."
  }
  if (/SHA-(256|384|512)/i.test(target)) {
    return "SHA-256 is hardware-accelerated on current CPUs and changes no message sizes — digest grows from 20 to 32 bytes."
  }
  if (/urandom|DRBG/i.test(target)) {
    return "A CSPRNG read is a syscall on the key-generation path only — no per-request cost."
  }
  return undefined
}

/**
 * F8 — the hybrid-preference rule. A high-criticality, external-facing asset is
 * the one place where the extra handshake bytes are worth paying: it is exposed
 * to harvest-now-decrypt-later capture *and* it cannot afford a PQC-only failure.
 */
function prefersHybrid(asset: CryptoAsset): boolean {
  return asset.classification.businessCriticality === "High" && asset.classification.facing === "External"
}

/** Applies the F8 weighting to a base recommendation. */
function weight(asset: CryptoAsset, rec: Recommendation): Recommendation {
  const performanceNote = performanceNoteFor(rec.primary)
  if (!rec.hybrid || !prefersHybrid(asset)) {
    return { ...rec, performanceNote }
  }
  return {
    ...rec,
    primary: rec.hybrid,
    hybrid: rec.hybrid,
    performanceNote: performanceNote
      ? `${performanceNote} Hybrid mode carries both key shares, so budget the classical bytes on top.`
      : undefined,
    latencyWeighted: true,
    notes:
      `${rec.notes} Latency-weighted choice: this asset is High business criticality and External-facing, so the hybrid ` +
      `suite is recommended over pure ${rec.primary} — the extra handshake bytes buy classical fallback on an exposed ` +
      `path, and the target is ${rec.primary} once the hybrid suite is proven in production.`,
  }
}

function baseRecommendation(asset: CryptoAsset): Recommendation | undefined {
  const highCriticality = asset.classification.businessCriticality === "High"

  // ------------------------------------------------------- key establishment
  if (asset.primitive === "key-agreement" || asset.primitive === "public-key-encryption") {
    const param = kemParamSet(asset.keySize)
    return {
      primary: param,
      standard: "FIPS 203 (ML-KEM)",
      hybrid: `X25519+${param} hybrid (draft-ietf-tls-hybrid-design)`,
      notes:
        `Replace ${asset.name} key establishment with ${param}. Public keys and ciphertexts are ~1.2 KB vs. 256 B for ` +
        `${asset.family === "ECC" ? "ECDH" : "RSA"} — budget for larger handshakes and MTU-sensitive paths. ` +
        (highCriticality
          ? "High-criticality path: deploy the hybrid suite first so a PQC implementation flaw cannot regress classical security."
          : "Hybrid mode is optional here; direct migration is acceptable."),
      complexity: asset.type === "protocol" ? "high" : "medium",
    }
  }

  // ---------------------------------------------------------------- signatures
  if (asset.primitive === "signature") {
    const param = dsaParamSet(asset.keySize)
    const isCert = asset.type === "certificate"
    return {
      primary: param,
      standard: "FIPS 204 (ML-DSA)",
      hybrid: isCert ? `Composite ML-DSA certificate (draft-ietf-lamps-pq-composite-sigs)` : `${param} alongside existing ECDSA during dual-signing window`,
      conservative: "SLH-DSA-SHA2-128s (FIPS 205) where signature-verification longevity outweighs size",
      notes:
        `Replace ${asset.name} signing with ${param}. Signatures grow to ~3.3 KB (ML-DSA-65); verify certificate ` +
        `chains, firmware slots and token sizes can absorb this. ` +
        (isCert ? "Reissue via a PQC-capable CA and dual-publish during the overlap." : "Roll out verify-first, then sign-first."),
      complexity: isCert ? "low" : "medium",
    }
  }

  // ----------------------------------------------------------------- protocols
  if (asset.type === "protocol") {
    if (asset.family === "TLS") {
      return {
        primary: "TLS 1.3 with X25519MLKEM768 group",
        standard: "FIPS 203 + RFC 8446",
        hybrid: "X25519MLKEM768 (already shipping in OpenSSL 3.5, BoringSSL, Chrome, Cloudflare)",
        notes:
          "Pin TLS 1.3 as the minimum version and enable the hybrid PQ key-exchange group. This closes the " +
          "harvest-now-decrypt-later window on recorded traffic without waiting for PQC certificates.",
        complexity: "medium",
      }
    }
    if (asset.family === "SSH") {
      return {
        primary: "sntrup761x25519-sha512 / mlkem768x25519-sha256 key exchange",
        standard: "OpenSSH 9.x+ PQ hybrid KEX",
        notes: "Enable the PQ hybrid KEX list and remove diffie-hellman-group14 / ecdh-sha2-nistp*. Host keys move to ML-DSA once your CA supports it.",
        complexity: "medium",
      }
    }
    if (asset.family === "JWT") {
      return {
        primary: "ML-DSA-44 (draft COSE/JOSE PQC algorithms)",
        standard: "FIPS 204 + draft-ietf-cose-dilithium",
        hybrid: "Keep ES256 verification enabled during rollout; reject `alg: none` and RS256 downgrade",
        notes: "Token lifetimes are short, so urgency is low — but the signing key itself is long-lived. Rotate to ML-DSA when your JOSE library ships it.",
        complexity: "low",
      }
    }
  }

  // -------------------------------------------- symmetric / hash / MAC / KDF
  if (asset.primitive === "encryption" || asset.primitive === "hash" || asset.primitive === "mac" || asset.primitive === "kdf") {
    if (asset.classicallyBroken) {
      const replacement =
        asset.family === "MD5" || asset.family === "SHA1"
          ? "SHA-256 (or SHA-384 for long-lived artefacts)"
          : "AES-256-GCM"
      return {
        primary: replacement,
        standard: asset.primitive === "hash" ? "FIPS 180-4 / SP 800-131A Rev. 2" : "FIPS 197 + SP 800-38D",
        notes: `${asset.name} is broken by classical attacks and must be removed regardless of the PQC timeline. Migrate to ${replacement}.`,
        complexity: "low",
      }
    }
    if ((asset.keySize ?? 0) < 256) {
      return {
        primary: `${asset.family === "AES" ? "AES-256" : `${asset.name} at 256-bit strength`}`,
        standard: "SP 800-131A Rev. 2 (Grover margin)",
        notes:
          "Not broken by Shor — Grover only halves effective strength. No replacement algorithm is needed; increase the " +
          "key or digest size to 256 bits so the post-quantum security level stays at 128 bits.",
        complexity: "low",
      }
    }
    return undefined
  }

  // ------------------------------------------------------------ weak RNG
  if (asset.primitive === "drbg") {
    return {
      primary: "secrets / os.urandom (SP 800-90A DRBG)",
      standard: "SP 800-90A Rev. 1",
      notes: "A non-cryptographic PRNG makes every downstream key predictable, quantum computer or not. Replace with the platform CSPRNG.",
      complexity: "low",
    }
  }

  // ---------------------------------------------------- unresolved libraries
  if (asset.type === "library") {
    return {
      primary: "Inventory the algorithms configured through this library",
      standard: "CycloneDX 1.6 CBOM coverage",
      notes:
        "Import-level evidence only: ECDAT knows the file reaches for cryptography but not which primitive is selected at " +
        "runtime. Add a call-level signature or review manually to close this gap.",
      complexity: "low",
    }
  }

  // ------------------------------------------------------- key material (F1)
  if (asset.type === "key") {
    if (asset.algorithmId === "hardcoded-key") {
      return {
        primary: "Remove the literal and rotate the key",
        standard: "SP 800-57 Part 1 Rev. 5 (key management)",
        notes:
          "An embedded key cannot be rotated without a code release, so treat the current value as compromised: move it to " +
          "a managed store (KMS, HSM, secret manager), rotate, then re-scan. Algorithm choice is a separate decision made " +
          "at the use site.",
        complexity: "low",
      }
    }
    return {
      primary: "Inventory the contained keys, then re-key with a PQC-capable algorithm",
      standard: "SP 800-57 Part 1 Rev. 5",
      conservative: "Keep the classical key alongside the PQC key during the overlap window",
      notes:
        "ECDAT records the key container, not its contents — nothing here was decrypted or parsed. Enumerate the keys, map " +
        "each to its use site, and re-key those protecting long-lived data first. Keystore formats (JKS/PKCS#12) must be " +
        "reissued to hold ML-KEM/ML-DSA material.",
      complexity: "medium",
    }
  }

  // ---------------------------------------------------- hardware module (F3)
  if (asset.type === "hardware-module") {
    return {
      primary: "Confirm FIPS 203/204 firmware support with the module vendor",
      standard: "PKCS#11 v3.0 + FIPS 140-3 validation",
      conservative: "Keep classical keys in the module and hold PQC keys in software until validated firmware ships",
      notes:
        "Reference detected in code — ECDAT never opened a PKCS#11 session, so this is not a live module inventory. The " +
        "migration is gated on vendor firmware: ML-KEM/ML-DSA mechanisms must exist in the module before any key can be " +
        "generated there, and FIPS 140-3 re-validation typically trails the firmware release.",
      complexity: "high",
    }
  }

  // ----------------------------------------------------- cloud service (F4)
  if (asset.type === "cloud-service") {
    return {
      primary: "Adopt the provider's PQC-capable key spec once available",
      standard: "FIPS 203/204 as exposed by the provider's key catalogue",
      conservative: "Wrap a PQC key under the existing managed key rather than waiting for native support",
      notes:
        "Reference detected in code — ECDAT made no API call, so the keys actually held in this service are not enumerated " +
        "here. Check the provider's supported key specs, then plan re-wrapping: managed keys cannot be re-keyed in place, " +
        "so each consumer needs a new key id and a dual-read window.",
      complexity: "medium",
    }
  }

  return undefined
}

export function recommendFor(asset: CryptoAsset): Recommendation | undefined {
  const base = baseRecommendation(asset)
  return base ? weight(asset, base) : undefined
}

export function applyRecommendations(assets: CryptoAsset[]): CryptoAsset[] {
  return assets.map((asset) => ({ ...asset, recommendation: recommendFor(asset) }))
}
