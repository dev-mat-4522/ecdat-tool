/**
 * ECDAT signature database.
 *
 * Two layers, kept separate on purpose:
 *   1. ALGORITHMS  — domain knowledge about the primitive itself
 *                    (primitive, key size, quantum status, NIST status).
 *   2. SIGNATURES   — the syntactic evidence that maps source code / config /
 *                    dependency tokens onto an algorithm id.
 *
 * Adding support for a new library is therefore a data change, not a code
 * change, which is what makes the scanner extensible (see README roadmap).
 */

import type { AlgorithmSpec, Language } from "./types"

export const ALGORITHMS: Record<string, AlgorithmSpec> = {
  // ---------------------------------------------------------------- asymmetric
  rsa: {
    id: "rsa",
    name: "RSA",
    family: "RSA",
    primitive: "public-key-encryption",
    assetType: "algorithm",
    defaultKeySize: 2048,
    quantumVulnerable: true,
    nistStatus: "Approved classically; deprecated for PQC (NSA CNSA 2.0)",
    defaultDataLifetime: 10,
    reference: "FIPS 186-5 / SP 800-56B",
    latencyNote: "RSA-2048 public key 256 B — small on the wire, but decryption is the slowest classical operation",
    latencyProfile: "moderate",
  },
  "rsa-signature": {
    id: "rsa-signature",
    name: "RSA (signature)",
    family: "RSA",
    primitive: "signature",
    assetType: "algorithm",
    defaultKeySize: 2048,
    quantumVulnerable: true,
    nistStatus: "Approved classically; deprecated for PQC (NSA CNSA 2.0)",
    defaultDataLifetime: 7,
    reference: "FIPS 186-5",
  },
  ecdsa: {
    id: "ecdsa",
    name: "ECDSA",
    family: "ECC",
    primitive: "signature",
    assetType: "algorithm",
    defaultKeySize: 256,
    quantumVulnerable: true,
    nistStatus: "Approved classically; deprecated for PQC",
    defaultDataLifetime: 7,
    reference: "FIPS 186-5",
  },
  ecdh: {
    id: "ecdh",
    name: "ECDH",
    family: "ECC",
    primitive: "key-agreement",
    assetType: "algorithm",
    defaultKeySize: 256,
    quantumVulnerable: true,
    nistStatus: "Approved classically; deprecated for PQC",
    defaultDataLifetime: 12,
    reference: "SP 800-56A",
    latencyNote: "ECDH P-256 shares 32-65 B per handshake — the baseline any PQC KEM is compared against",
    latencyProfile: "light",
  },
  ec: {
    id: "ec",
    name: "Elliptic Curve (unspecified use)",
    family: "ECC",
    primitive: "other",
    assetType: "algorithm",
    defaultKeySize: 256,
    quantumVulnerable: true,
    nistStatus: "Approved classically; deprecated for PQC",
    defaultDataLifetime: 8,
  },
  ed25519: {
    id: "ed25519",
    name: "Ed25519",
    family: "ECC",
    primitive: "signature",
    assetType: "algorithm",
    defaultKeySize: 256,
    quantumVulnerable: true,
    nistStatus: "Approved (FIPS 186-5); quantum-vulnerable",
    defaultDataLifetime: 7,
  },
  x25519: {
    id: "x25519",
    name: "X25519",
    family: "ECC",
    primitive: "key-agreement",
    assetType: "algorithm",
    defaultKeySize: 256,
    quantumVulnerable: true,
    nistStatus: "Widely deployed; quantum-vulnerable",
    defaultDataLifetime: 12,
  },
  dh: {
    id: "dh",
    name: "Diffie-Hellman (finite field)",
    family: "DH",
    primitive: "key-agreement",
    assetType: "algorithm",
    defaultKeySize: 2048,
    quantumVulnerable: true,
    nistStatus: "Approved classically; deprecated for PQC",
    defaultDataLifetime: 12,
  },
  dsa: {
    id: "dsa",
    name: "DSA",
    family: "DSA",
    primitive: "signature",
    assetType: "algorithm",
    defaultKeySize: 2048,
    quantumVulnerable: true,
    nistStatus: "Disallowed for signature generation after 2023 (SP 800-131A)",
    defaultDataLifetime: 5,
  },

  // ----------------------------------------------------------------- symmetric
  aes: {
    id: "aes",
    name: "AES",
    family: "AES",
    primitive: "encryption",
    assetType: "algorithm",
    defaultKeySize: 128,
    quantumVulnerable: false,
    groverWeakened: true,
    nistStatus: "Approved (FIPS 197); PQC-safe at >=256-bit keys",
    defaultDataLifetime: 10,
  },
  chacha20: {
    id: "chacha20",
    name: "ChaCha20-Poly1305",
    family: "ChaCha",
    primitive: "encryption",
    assetType: "algorithm",
    defaultKeySize: 256,
    quantumVulnerable: false,
    groverWeakened: true,
    nistStatus: "RFC 8439; PQC-safe",
    defaultDataLifetime: 10,
  },
  "3des": {
    id: "3des",
    name: "Triple DES",
    family: "DES",
    primitive: "encryption",
    assetType: "algorithm",
    defaultKeySize: 112,
    quantumVulnerable: false,
    groverWeakened: true,
    classicallyBroken: true,
    nistStatus: "Disallowed after 2023 (SP 800-131A Rev. 2)",
    defaultDataLifetime: 10,
  },
  des: {
    id: "des",
    name: "DES",
    family: "DES",
    primitive: "encryption",
    assetType: "algorithm",
    defaultKeySize: 56,
    quantumVulnerable: false,
    groverWeakened: true,
    classicallyBroken: true,
    nistStatus: "Withdrawn",
    defaultDataLifetime: 10,
  },
  rc4: {
    id: "rc4",
    name: "RC4",
    family: "RC4",
    primitive: "encryption",
    assetType: "algorithm",
    defaultKeySize: 128,
    quantumVulnerable: false,
    classicallyBroken: true,
    nistStatus: "Prohibited (RFC 7465)",
    defaultDataLifetime: 10,
  },
  blowfish: {
    id: "blowfish",
    name: "Blowfish",
    family: "Blowfish",
    primitive: "encryption",
    assetType: "algorithm",
    defaultKeySize: 128,
    quantumVulnerable: false,
    classicallyBroken: true,
    nistStatus: "Not NIST-approved; 64-bit block deprecated",
    defaultDataLifetime: 10,
  },

  // ---------------------------------------------------------------------- hash
  md5: {
    id: "md5",
    name: "MD5",
    family: "MD5",
    primitive: "hash",
    assetType: "algorithm",
    defaultKeySize: 128,
    quantumVulnerable: false,
    classicallyBroken: true,
    nistStatus: "Collision-broken; prohibited for digital signatures",
    defaultDataLifetime: 5,
  },
  sha1: {
    id: "sha1",
    name: "SHA-1",
    family: "SHA1",
    primitive: "hash",
    assetType: "algorithm",
    defaultKeySize: 160,
    quantumVulnerable: false,
    classicallyBroken: true,
    nistStatus: "Withdrawn for most uses by 2030 (NIST IR 8547 draft)",
    defaultDataLifetime: 5,
  },
  sha256: {
    id: "sha256",
    name: "SHA-256",
    family: "SHA2",
    primitive: "hash",
    assetType: "algorithm",
    defaultKeySize: 256,
    quantumVulnerable: false,
    groverWeakened: true,
    nistStatus: "Approved (FIPS 180-4); PQC-safe",
    defaultDataLifetime: 10,
  },
  sha512: {
    id: "sha512",
    name: "SHA-512",
    family: "SHA2",
    primitive: "hash",
    assetType: "algorithm",
    defaultKeySize: 512,
    quantumVulnerable: false,
    nistStatus: "Approved (FIPS 180-4); PQC-safe",
    defaultDataLifetime: 10,
  },
  sha3: {
    id: "sha3",
    name: "SHA-3",
    family: "SHA3",
    primitive: "hash",
    assetType: "algorithm",
    defaultKeySize: 256,
    quantumVulnerable: false,
    nistStatus: "Approved (FIPS 202); PQC-safe",
    defaultDataLifetime: 10,
  },
  hmac: {
    id: "hmac",
    name: "HMAC",
    family: "HMAC",
    primitive: "mac",
    assetType: "algorithm",
    defaultKeySize: 256,
    quantumVulnerable: false,
    groverWeakened: true,
    nistStatus: "Approved (FIPS 198-1); PQC-safe",
    defaultDataLifetime: 8,
  },
  pbkdf2: {
    id: "pbkdf2",
    name: "PBKDF2",
    family: "KDF",
    primitive: "kdf",
    assetType: "algorithm",
    defaultKeySize: 256,
    quantumVulnerable: false,
    groverWeakened: true,
    nistStatus: "Approved (SP 800-132)",
    defaultDataLifetime: 8,
  },
  bcrypt: {
    id: "bcrypt",
    name: "bcrypt",
    family: "KDF",
    primitive: "kdf",
    assetType: "algorithm",
    defaultKeySize: 184,
    quantumVulnerable: false,
    nistStatus: "Not NIST-approved but acceptable for password storage",
    defaultDataLifetime: 8,
  },

  // ---------------------------------------------------------------------- prng
  "weak-random": {
    id: "weak-random",
    name: "Non-cryptographic RNG",
    family: "RNG",
    primitive: "drbg",
    assetType: "algorithm",
    quantumVulnerable: false,
    classicallyBroken: true,
    nistStatus: "Not approved for cryptographic use (SP 800-90A)",
    defaultDataLifetime: 5,
  },

  // ------------------------------------------------------------------ protocol
  "tls1.0": {
    id: "tls1.0",
    name: "TLS 1.0",
    family: "TLS",
    primitive: "protocol",
    assetType: "protocol",
    quantumVulnerable: true,
    classicallyBroken: true,
    nistStatus: "Prohibited (RFC 8996)",
    defaultDataLifetime: 12,
  },
  "tls1.1": {
    id: "tls1.1",
    name: "TLS 1.1",
    family: "TLS",
    primitive: "protocol",
    assetType: "protocol",
    quantumVulnerable: true,
    classicallyBroken: true,
    nistStatus: "Prohibited (RFC 8996)",
    defaultDataLifetime: 12,
  },
  "tls1.2": {
    id: "tls1.2",
    name: "TLS 1.2",
    family: "TLS",
    primitive: "protocol",
    assetType: "protocol",
    quantumVulnerable: true,
    nistStatus: "Approved; key exchange is quantum-vulnerable",
    defaultDataLifetime: 12,
  },
  "tls1.3": {
    id: "tls1.3",
    name: "TLS 1.3",
    family: "TLS",
    primitive: "protocol",
    assetType: "protocol",
    quantumVulnerable: true,
    nistStatus: "Approved; classical key exchange remains quantum-vulnerable",
    defaultDataLifetime: 12,
  },
  ssh: {
    id: "ssh",
    name: "SSH",
    family: "SSH",
    primitive: "protocol",
    assetType: "protocol",
    quantumVulnerable: true,
    nistStatus: "Key exchange quantum-vulnerable unless PQ hybrid enabled",
    defaultDataLifetime: 10,
  },
  jwt: {
    id: "jwt",
    name: "JWT signing",
    family: "JWT",
    primitive: "signature",
    assetType: "protocol",
    quantumVulnerable: true,
    nistStatus: "Depends on `alg`; RS256/ES256 are quantum-vulnerable",
    defaultDataLifetime: 3,
  },

  // ------------------------------------------------------------- already-PQC
  "ml-kem": {
    id: "ml-kem",
    name: "ML-KEM (Kyber)",
    family: "PQC",
    primitive: "key-encapsulation",
    assetType: "algorithm",
    defaultKeySize: 768,
    quantumVulnerable: false,
    nistStatus: "Standardized (FIPS 203)",
    defaultDataLifetime: 15,
    latencyNote: "ML-KEM-768 public key ~1.2 KB and ciphertext ~1.1 KB vs. X25519's 32 B — one extra TLS record on most handshakes",
    latencyProfile: "moderate",
  },
  "ml-dsa": {
    id: "ml-dsa",
    name: "ML-DSA (Dilithium)",
    family: "PQC",
    primitive: "signature",
    assetType: "algorithm",
    quantumVulnerable: false,
    nistStatus: "Standardized (FIPS 204)",
    defaultDataLifetime: 15,
    latencyNote: "ML-DSA-65 signature ~3.3 KB vs. RSA-2048's 256 B — inflates certificate chains and JWT payloads",
    latencyProfile: "heavy",
  },
  "slh-dsa": {
    id: "slh-dsa",
    name: "SLH-DSA (SPHINCS+)",
    family: "PQC",
    primitive: "signature",
    assetType: "algorithm",
    quantumVulnerable: false,
    nistStatus: "Standardized (FIPS 205)",
    defaultDataLifetime: 20,
    latencyNote: "SLH-DSA-128s signature ~7.9 KB and slow signing — suited to firmware/root-of-trust, not per-request paths",
    latencyProfile: "heavy",
  },

  // ---------------------------------------------------------- key material (F1)
  "key-material": {
    id: "key-material",
    name: "Key material",
    family: "KEY",
    primitive: "other",
    assetType: "key",
    quantumVulnerable: true,
    nistStatus: "Standalone key material — algorithm determined at the use site (SP 800-57)",
    defaultDataLifetime: 12,
    reference: "SP 800-57 Part 1 Rev. 5",
  },
  keystore: {
    id: "keystore",
    name: "Keystore container",
    family: "KEY",
    primitive: "other",
    assetType: "key",
    quantumVulnerable: true,
    nistStatus: "Keystore (JKS / PKCS#12) — inspect contained keys before migration",
    defaultDataLifetime: 12,
    reference: "RFC 7292 (PKCS#12)",
  },
  "hardcoded-key": {
    id: "hardcoded-key",
    name: "Hardcoded key material",
    family: "KEY",
    primitive: "other",
    assetType: "key",
    quantumVulnerable: true,
    classicallyBroken: true,
    nistStatus: "Key management violation — embedded secrets cannot be rotated (SP 800-57)",
    defaultDataLifetime: 12,
  },

  // ------------------------------------------------------ hardware module (F3)
  hsm: {
    id: "hsm",
    name: "Hardware security module",
    family: "HSM",
    primitive: "other",
    assetType: "hardware-module",
    quantumVulnerable: true,
    nistStatus: "PQC availability depends on HSM firmware — confirm vendor roadmap",
    defaultDataLifetime: 15,
    reference: "PKCS#11 v3.0",
  },

  // -------------------------------------------------------- cloud service (F4)
  "cloud-kms": {
    id: "cloud-kms",
    name: "Cloud key management service",
    family: "KMS",
    primitive: "other",
    assetType: "cloud-service",
    quantumVulnerable: true,
    nistStatus: "PQC availability depends on the provider's algorithm catalogue",
    defaultDataLifetime: 15,
  },

  // ------------------------------------------------------------------- library
  "crypto-library": {
    id: "crypto-library",
    name: "Cryptographic library",
    family: "LIBRARY",
    primitive: "other",
    assetType: "library",
    quantumVulnerable: false,
    nistStatus: "Depends on configured algorithms",
    defaultDataLifetime: 5,
  },
  "x509-certificate": {
    id: "x509-certificate",
    name: "X.509 certificate",
    family: "CERT",
    primitive: "signature",
    assetType: "certificate",
    quantumVulnerable: true,
    nistStatus: "Signature algorithm dependent",
    defaultDataLifetime: 5,
  },
}

/** Modules that mean "this file touches cryptography" for import-level detection. */
export interface ImportSignature {
  module: string
  algorithmId: string
  /** Library name recorded for the dependency graph. */
  library: string
  note?: string
}

/** Call-level signature: the highest-precision evidence class. */
export interface CallSignature {
  /** Fully-qualified dotted call name after alias resolution. */
  call: string
  algorithmId: string
  library: string
  /** Positional argument index that carries the key size, if any. */
  keySizeArg?: number
  /** Argument index carrying an algorithm name string (e.g. jwt algorithms). */
  algorithmArg?: number
}

export const PYTHON_IMPORTS: ImportSignature[] = [
  { module: "hashlib", algorithmId: "crypto-library", library: "hashlib" },
  { module: "hmac", algorithmId: "hmac", library: "hmac" },
  { module: "ssl", algorithmId: "tls1.2", library: "ssl", note: "TLS context construction" },
  { module: "secrets", algorithmId: "crypto-library", library: "secrets" },
  // NOTE: `import random` alone is not a finding — plenty of code uses it for
  // jitter or sampling. Only the generator *calls* below are reported, which
  // keeps the weak-RNG signal precise instead of noisy.
  { module: "Crypto", algorithmId: "crypto-library", library: "pycryptodome" },
  { module: "Cryptodome", algorithmId: "crypto-library", library: "pycryptodome" },
  { module: "cryptography", algorithmId: "crypto-library", library: "pyca/cryptography" },
  { module: "OpenSSL", algorithmId: "crypto-library", library: "pyOpenSSL" },
  { module: "nacl", algorithmId: "crypto-library", library: "PyNaCl" },
  { module: "jwt", algorithmId: "jwt", library: "PyJWT" },
  { module: "jose", algorithmId: "jwt", library: "python-jose" },
  { module: "paramiko", algorithmId: "ssh", library: "paramiko" },
  { module: "bcrypt", algorithmId: "bcrypt", library: "bcrypt" },
  { module: "passlib", algorithmId: "pbkdf2", library: "passlib" },
  { module: "oqs", algorithmId: "ml-kem", library: "liboqs-python", note: "Post-quantum library already in use" },
  { module: "pqcrypto", algorithmId: "ml-kem", library: "pqcrypto" },
]

export const PYTHON_CALLS: CallSignature[] = [
  // hashlib
  { call: "hashlib.md5", algorithmId: "md5", library: "hashlib" },
  { call: "hashlib.sha1", algorithmId: "sha1", library: "hashlib" },
  { call: "hashlib.sha224", algorithmId: "sha256", library: "hashlib" },
  { call: "hashlib.sha256", algorithmId: "sha256", library: "hashlib" },
  { call: "hashlib.sha384", algorithmId: "sha512", library: "hashlib" },
  { call: "hashlib.sha512", algorithmId: "sha512", library: "hashlib" },
  { call: "hashlib.sha3_256", algorithmId: "sha3", library: "hashlib" },
  { call: "hashlib.sha3_512", algorithmId: "sha3", library: "hashlib" },
  { call: "hashlib.blake2b", algorithmId: "sha3", library: "hashlib" },
  { call: "hashlib.new", algorithmId: "crypto-library", library: "hashlib", algorithmArg: 0 },
  { call: "hashlib.pbkdf2_hmac", algorithmId: "pbkdf2", library: "hashlib" },
  { call: "hmac.new", algorithmId: "hmac", library: "hmac" },
  { call: "hmac.digest", algorithmId: "hmac", library: "hmac" },

  // pycryptodome
  { call: "Crypto.PublicKey.RSA.generate", algorithmId: "rsa", library: "pycryptodome", keySizeArg: 0 },
  { call: "RSA.generate", algorithmId: "rsa", library: "pycryptodome", keySizeArg: 0 },
  { call: "RSA.import_key", algorithmId: "rsa", library: "pycryptodome" },
  { call: "RSA.importKey", algorithmId: "rsa", library: "pycryptodome" },
  { call: "PKCS1_v1_5.new", algorithmId: "rsa-signature", library: "pycryptodome" },
  { call: "PKCS1_OAEP.new", algorithmId: "rsa", library: "pycryptodome" },
  { call: "pss.new", algorithmId: "rsa-signature", library: "pycryptodome" },
  { call: "DSA.generate", algorithmId: "dsa", library: "pycryptodome", keySizeArg: 0 },
  { call: "ECC.generate", algorithmId: "ec", library: "pycryptodome" },
  { call: "DSS.new", algorithmId: "ecdsa", library: "pycryptodome" },
  { call: "AES.new", algorithmId: "aes", library: "pycryptodome" },
  { call: "DES.new", algorithmId: "des", library: "pycryptodome" },
  { call: "DES3.new", algorithmId: "3des", library: "pycryptodome" },
  { call: "ARC4.new", algorithmId: "rc4", library: "pycryptodome" },
  { call: "Blowfish.new", algorithmId: "blowfish", library: "pycryptodome" },
  { call: "ChaCha20.new", algorithmId: "chacha20", library: "pycryptodome" },
  { call: "ChaCha20_Poly1305.new", algorithmId: "chacha20", library: "pycryptodome" },
  { call: "MD5.new", algorithmId: "md5", library: "pycryptodome" },
  { call: "SHA1.new", algorithmId: "sha1", library: "pycryptodome" },
  { call: "SHA256.new", algorithmId: "sha256", library: "pycryptodome" },

  // pyca/cryptography
  { call: "rsa.generate_private_key", algorithmId: "rsa", library: "pyca/cryptography" },
  { call: "asymmetric.rsa.generate_private_key", algorithmId: "rsa", library: "pyca/cryptography" },
  { call: "ec.generate_private_key", algorithmId: "ecdsa", library: "pyca/cryptography" },
  { call: "ec.ECDH", algorithmId: "ecdh", library: "pyca/cryptography" },
  { call: "dh.generate_parameters", algorithmId: "dh", library: "pyca/cryptography", keySizeArg: 1 },
  { call: "dsa.generate_private_key", algorithmId: "dsa", library: "pyca/cryptography" },
  { call: "ed25519.Ed25519PrivateKey.generate", algorithmId: "ed25519", library: "pyca/cryptography" },
  { call: "x25519.X25519PrivateKey.generate", algorithmId: "x25519", library: "pyca/cryptography" },
  { call: "Cipher", algorithmId: "crypto-library", library: "pyca/cryptography" },
  { call: "algorithms.AES", algorithmId: "aes", library: "pyca/cryptography", keySizeArg: -1 },
  { call: "algorithms.TripleDES", algorithmId: "3des", library: "pyca/cryptography" },
  { call: "algorithms.ARC4", algorithmId: "rc4", library: "pyca/cryptography" },
  { call: "algorithms.Blowfish", algorithmId: "blowfish", library: "pyca/cryptography" },
  { call: "algorithms.ChaCha20", algorithmId: "chacha20", library: "pyca/cryptography" },
  { call: "hashes.MD5", algorithmId: "md5", library: "pyca/cryptography" },
  { call: "hashes.SHA1", algorithmId: "sha1", library: "pyca/cryptography" },
  { call: "hashes.SHA256", algorithmId: "sha256", library: "pyca/cryptography" },
  { call: "hashes.SHA512", algorithmId: "sha512", library: "pyca/cryptography" },
  { call: "hashes.SHA3_256", algorithmId: "sha3", library: "pyca/cryptography" },
  { call: "padding.PKCS1v15", algorithmId: "rsa", library: "pyca/cryptography" },
  { call: "padding.OAEP", algorithmId: "rsa", library: "pyca/cryptography" },
  { call: "PBKDF2HMAC", algorithmId: "pbkdf2", library: "pyca/cryptography" },
  { call: "Fernet", algorithmId: "aes", library: "pyca/cryptography" },
  { call: "x509.load_pem_x509_certificate", algorithmId: "x509-certificate", library: "pyca/cryptography" },
  { call: "x509.CertificateBuilder", algorithmId: "x509-certificate", library: "pyca/cryptography" },

  // TLS / SSH / JWT
  { call: "ssl.SSLContext", algorithmId: "tls1.2", library: "ssl" },
  { call: "ssl.wrap_socket", algorithmId: "tls1.0", library: "ssl" },
  { call: "ssl.create_default_context", algorithmId: "tls1.3", library: "ssl" },
  { call: "paramiko.SSHClient", algorithmId: "ssh", library: "paramiko" },
  { call: "paramiko.RSAKey.generate", algorithmId: "rsa", library: "paramiko", keySizeArg: 0 },
  { call: "jwt.encode", algorithmId: "jwt", library: "PyJWT" },
  { call: "jwt.decode", algorithmId: "jwt", library: "PyJWT" },
  { call: "bcrypt.hashpw", algorithmId: "bcrypt", library: "bcrypt" },
  { call: "random.random", algorithmId: "weak-random", library: "random" },
  { call: "random.randint", algorithmId: "weak-random", library: "random" },
  { call: "random.choice", algorithmId: "weak-random", library: "random" },
  { call: "random.getrandbits", algorithmId: "weak-random", library: "random" },
  { call: "random.randrange", algorithmId: "weak-random", library: "random" },
  { call: "random.sample", algorithmId: "weak-random", library: "random" },
  { call: "random.shuffle", algorithmId: "weak-random", library: "random" },
  { call: "random.uniform", algorithmId: "weak-random", library: "random" },
  { call: "oqs.KeyEncapsulation", algorithmId: "ml-kem", library: "liboqs-python" },
  { call: "oqs.Signature", algorithmId: "ml-dsa", library: "liboqs-python" },
]

/**
 * Regex-based signatures for languages where ECDAT has no parser.
 * Library/statement-level precision only — documented limitation.
 */
export interface RegexSignature {
  id: string
  pattern: RegExp
  algorithmId: string
  library: string
  language: Language
  kind: "import" | "call" | "string-literal"
  /** Capture group index holding a key size. */
  keySizeGroup?: number
  /** Capture group index holding an algorithm name to re-resolve. */
  algorithmGroup?: number
}

export const REGEX_SIGNATURES: RegexSignature[] = [
  // ------------------------------------------------------------------- Java
  { id: "java-javax-crypto", pattern: /import\s+javax\.crypto[.\w*]*/g, algorithmId: "crypto-library", library: "javax.crypto", language: "java", kind: "import" },
  { id: "java-security", pattern: /import\s+java\.security[.\w*]*/g, algorithmId: "crypto-library", library: "java.security", language: "java", kind: "import" },
  { id: "java-bouncycastle", pattern: /import\s+org\.bouncycastle[.\w*]*/g, algorithmId: "crypto-library", library: "BouncyCastle", language: "java", kind: "import" },
  { id: "java-cipher-getinstance", pattern: /Cipher\.getInstance\(\s*"([^"]+)"/g, algorithmId: "crypto-library", library: "javax.crypto", language: "java", kind: "call", algorithmGroup: 1 },
  { id: "java-messagedigest", pattern: /MessageDigest\.getInstance\(\s*"([^"]+)"/g, algorithmId: "crypto-library", library: "java.security", language: "java", kind: "call", algorithmGroup: 1 },
  { id: "java-signature", pattern: /Signature\.getInstance\(\s*"([^"]+)"/g, algorithmId: "crypto-library", library: "java.security", language: "java", kind: "call", algorithmGroup: 1 },
  { id: "java-keypairgen", pattern: /KeyPairGenerator\.getInstance\(\s*"([^"]+)"/g, algorithmId: "crypto-library", library: "java.security", language: "java", kind: "call", algorithmGroup: 1 },
  { id: "java-keygen-init", pattern: /initialize\(\s*(\d{3,5})\s*\)/g, algorithmId: "rsa", library: "java.security", language: "java", kind: "call", keySizeGroup: 1 },
  { id: "java-sslcontext", pattern: /SSLContext\.getInstance\(\s*"(TLSv?1?\.?\d?)"/g, algorithmId: "crypto-library", library: "javax.net.ssl", language: "java", kind: "call", algorithmGroup: 1 },
  { id: "java-securerandom", pattern: /new\s+Random\s*\(/g, algorithmId: "weak-random", library: "java.util", language: "java", kind: "call" },

  // ------------------------------------------------------------- JavaScript
  { id: "js-node-crypto", pattern: /require\(\s*['"](?:node:)?crypto['"]\s*\)|from\s+['"](?:node:)?crypto['"]/g, algorithmId: "crypto-library", library: "node:crypto", language: "javascript", kind: "import" },
  { id: "js-createhash", pattern: /createHash\(\s*['"]([\w-]+)['"]/g, algorithmId: "crypto-library", library: "node:crypto", language: "javascript", kind: "call", algorithmGroup: 1 },
  { id: "js-createhmac", pattern: /createHmac\(\s*['"]([\w-]+)['"]/g, algorithmId: "hmac", library: "node:crypto", language: "javascript", kind: "call" },
  { id: "js-createcipher", pattern: /createCipheriv\(\s*['"]([\w-]+)['"]/g, algorithmId: "crypto-library", library: "node:crypto", language: "javascript", kind: "call", algorithmGroup: 1 },
  { id: "js-generatekeypair", pattern: /generateKeyPair(?:Sync)?\(\s*['"]([\w]+)['"]/g, algorithmId: "crypto-library", library: "node:crypto", language: "javascript", kind: "call", algorithmGroup: 1 },
  { id: "js-modulus", pattern: /modulusLength\s*:\s*(\d{3,5})/g, algorithmId: "rsa", library: "node:crypto", language: "javascript", kind: "call", keySizeGroup: 1 },
  { id: "js-jsonwebtoken", pattern: /require\(\s*['"]jsonwebtoken['"]|from\s+['"]jsonwebtoken['"]/g, algorithmId: "jwt", library: "jsonwebtoken", language: "javascript", kind: "import" },
  { id: "js-jwt-alg", pattern: /algorithm\s*:\s*['"](RS256|RS512|ES256|ES384|HS256|HS512|PS256|EdDSA)['"]/g, algorithmId: "jwt", library: "jsonwebtoken", language: "javascript", kind: "call", algorithmGroup: 1 },
  { id: "js-bcrypt", pattern: /require\(\s*['"]bcrypt(?:js)?['"]|from\s+['"]bcrypt(?:js)?['"]/g, algorithmId: "bcrypt", library: "bcrypt", language: "javascript", kind: "import" },
  { id: "js-mathrandom", pattern: /Math\.random\(\)/g, algorithmId: "weak-random", library: "ecmascript", language: "javascript", kind: "call" },
  { id: "js-node-forge", pattern: /require\(\s*['"]node-forge['"]|from\s+['"]node-forge['"]/g, algorithmId: "crypto-library", library: "node-forge", language: "javascript", kind: "import" },

  // -------------------------------------------------------------------- Go
  { id: "go-crypto-rsa", pattern: /"crypto\/rsa"/g, algorithmId: "rsa", library: "crypto/rsa", language: "go", kind: "import" },
  { id: "go-crypto-ecdsa", pattern: /"crypto\/ecdsa"/g, algorithmId: "ecdsa", library: "crypto/ecdsa", language: "go", kind: "import" },
  { id: "go-crypto-ed25519", pattern: /"crypto\/ed25519"/g, algorithmId: "ed25519", library: "crypto/ed25519", language: "go", kind: "import" },
  { id: "go-crypto-aes", pattern: /"crypto\/aes"/g, algorithmId: "aes", library: "crypto/aes", language: "go", kind: "import" },
  { id: "go-crypto-des", pattern: /"crypto\/des"/g, algorithmId: "des", library: "crypto/des", language: "go", kind: "import" },
  { id: "go-crypto-md5", pattern: /"crypto\/md5"/g, algorithmId: "md5", library: "crypto/md5", language: "go", kind: "import" },
  { id: "go-crypto-sha1", pattern: /"crypto\/sha1"/g, algorithmId: "sha1", library: "crypto/sha1", language: "go", kind: "import" },
  { id: "go-crypto-tls", pattern: /"crypto\/tls"/g, algorithmId: "tls1.3", library: "crypto/tls", language: "go", kind: "import" },
  { id: "go-rsa-generate", pattern: /rsa\.GenerateKey\([^,]+,\s*(\d{3,5})\)/g, algorithmId: "rsa", library: "crypto/rsa", language: "go", kind: "call", keySizeGroup: 1 },
  { id: "go-mathrand", pattern: /"math\/rand"/g, algorithmId: "weak-random", library: "math/rand", language: "go", kind: "import" },

  // ------------------------------------------------------------------ C#
  { id: "cs-crypto-ns", pattern: /using\s+System\.Security\.Cryptography\s*;/g, algorithmId: "crypto-library", library: "System.Security.Cryptography", language: "csharp", kind: "import" },
  { id: "cs-rsa-create", pattern: /RSA\.Create\(\s*(\d{3,5})?\s*\)/g, algorithmId: "rsa", library: "System.Security.Cryptography", language: "csharp", kind: "call", keySizeGroup: 1 },
  { id: "cs-md5", pattern: /MD5\.Create\(\)/g, algorithmId: "md5", library: "System.Security.Cryptography", language: "csharp", kind: "call" },
  { id: "cs-sha1", pattern: /SHA1\.Create\(\)/g, algorithmId: "sha1", library: "System.Security.Cryptography", language: "csharp", kind: "call" },
  { id: "cs-aes", pattern: /Aes\.Create\(\)/g, algorithmId: "aes", library: "System.Security.Cryptography", language: "csharp", kind: "call" },
]

/** Configuration-file directives (TLS versions, cipher suites, SSH kex). */
export const CONFIG_SIGNATURES: RegexSignature[] = [
  { id: "cfg-tls10", pattern: /\b(TLSv1|TLSv1\.0|SSLv3|SSLv2)\b/g, algorithmId: "tls1.0", library: "tls-config", language: "config", kind: "config" as never as "call" },
  { id: "cfg-tls11", pattern: /\bTLSv1\.1\b/g, algorithmId: "tls1.1", library: "tls-config", language: "config", kind: "call" },
  { id: "cfg-tls12", pattern: /\bTLSv1\.2\b/g, algorithmId: "tls1.2", library: "tls-config", language: "config", kind: "call" },
  { id: "cfg-tls13", pattern: /\bTLSv1\.3\b/g, algorithmId: "tls1.3", library: "tls-config", language: "config", kind: "call" },
  { id: "cfg-ecdhe", pattern: /\bECDHE[-_][A-Z0-9-]+\b/g, algorithmId: "ecdh", library: "cipher-suite", language: "config", kind: "call" },
  { id: "cfg-dhe", pattern: /\bDHE[-_][A-Z0-9-]+\b/g, algorithmId: "dh", library: "cipher-suite", language: "config", kind: "call" },
  { id: "cfg-rsa-suite", pattern: /\bTLS_RSA_WITH_[A-Z0-9_]+\b/g, algorithmId: "rsa", library: "cipher-suite", language: "config", kind: "call" },
  { id: "cfg-rc4", pattern: /\bRC4(?:[-_][A-Z0-9]+)?\b/g, algorithmId: "rc4", library: "cipher-suite", language: "config", kind: "call" },
  { id: "cfg-3des", pattern: /\b(3DES|DES-CBC3)\b/g, algorithmId: "3des", library: "cipher-suite", language: "config", kind: "call" },
  { id: "cfg-md5-suite", pattern: /\b[A-Z0-9-]*MD5\b/g, algorithmId: "md5", library: "cipher-suite", language: "config", kind: "call" },
  { id: "cfg-ssh-kex", pattern: /\b(diffie-hellman-group\d+-sha\d+|curve25519-sha256|ecdh-sha2-nistp\d+)\b/g, algorithmId: "ecdh", library: "ssh-config", language: "config", kind: "call" },
  { id: "cfg-ssh-hostkey", pattern: /\b(ssh-rsa|rsa-sha2-\d+|ecdsa-sha2-nistp\d+|ssh-ed25519)\b/g, algorithmId: "rsa-signature", library: "ssh-config", language: "config", kind: "call" },
]

/**
 * Reference signatures (F3 / F4).
 *
 * These do not describe an algorithm the code executes — they describe an
 * *integration* with something that holds keys elsewhere. They are therefore
 * catalogued as their own artefact types and every finding carries a scope
 * caption (U5): ECDAT reports that the codebase talks to an HSM or a cloud KMS,
 * it never connects to one or enumerates the keys inside it.
 */
export interface ReferenceSignature {
  id: string
  pattern: RegExp
  algorithmId: string
  assetType: "hardware-module" | "cloud-service"
  /** Human label used as the artefact name, e.g. `AWS KMS`. */
  label: string
  /** Vendor/SDK recorded as evidence detail. */
  library: string
  kind: "import" | "call" | "config"
}

export const HSM_SIGNATURES: ReferenceSignature[] = [
  { id: "hsm-pkcs11-import", pattern: /\b(?:import|require|using)\b[^\n;]*\b(pkcs11|PKCS11|Pkcs11Interop|iaik\.pkcs\.pkcs11|sun\.security\.pkcs11)\b/g, algorithmId: "hsm", assetType: "hardware-module", label: "PKCS#11 HSM integration", library: "PKCS#11", kind: "import" },
  { id: "hsm-pkcs11-provider", pattern: /\bSunPKCS11\b|\bPKCS11Provider\b|\bC_(?:Initialize|OpenSession|GenerateKeyPair|Sign)\b/g, algorithmId: "hsm", assetType: "hardware-module", label: "PKCS#11 HSM integration", library: "PKCS#11", kind: "call" },
  { id: "hsm-pkcs11-config", pattern: /^[^\n]*\b(pkcs11\.library|pkcs11\.slot|hsm\.provider|hsm\.slot|hsm\.pin|hsm\.partition|softhsm)\b[^\n]*/gim, algorithmId: "hsm", assetType: "hardware-module", label: "PKCS#11 HSM configuration", library: "HSM config", kind: "config" },
  { id: "hsm-thales-luna", pattern: /\b(LunaSlotManager|LunaProvider|com\.safenetinc\.luna|thales(?:group)?\.(?:luna|hsm)|gemalto\.luna)\b/gi, algorithmId: "hsm", assetType: "hardware-module", label: "Thales Luna HSM", library: "Thales Luna SDK", kind: "import" },
  { id: "hsm-aws-cloudhsm", pattern: /\b(cloudhsm|CloudHsm|cavium|com\.amazonaws\.cloudhsm)\b/g, algorithmId: "hsm", assetType: "hardware-module", label: "AWS CloudHSM", library: "AWS CloudHSM client", kind: "import" },
  { id: "hsm-utimaco-entrust", pattern: /\b(CryptoServer|utimaco|nCipher|nShield|entrust\.hsm)\b/gi, algorithmId: "hsm", assetType: "hardware-module", label: "Utimaco / Entrust nShield HSM", library: "vendor HSM SDK", kind: "import" },
  { id: "hsm-yubi-tpm", pattern: /\b(yubihsm|tpm2_|Tpm2Lib|TSS2_)\w*/g, algorithmId: "hsm", assetType: "hardware-module", label: "YubiHSM / TPM 2.0", library: "hardware key store", kind: "import" },
]

export const CLOUD_SIGNATURES: ReferenceSignature[] = [
  { id: "kms-aws-sdk", pattern: /\b(?:boto3\.client\(\s*["']kms["']|aws-sdk\/client-kms|com\.amazonaws\.services\.kms|software\.amazon\.awssdk\.services\.kms|Aws\\\\Kms|aws_kms_client|KMSClient|AWSKMSClient)\b/g, algorithmId: "cloud-kms", assetType: "cloud-service", label: "AWS KMS", library: "AWS KMS SDK", kind: "import" },
  { id: "kms-aws-arn", pattern: /arn:aws:kms:[a-z0-9-]+:\d+:key\/[\w-]+/g, algorithmId: "cloud-kms", assetType: "cloud-service", label: "AWS KMS", library: "AWS KMS key ARN", kind: "config" },
  { id: "kms-aws-terraform", pattern: /resource\s+"aws_kms_(?:key|alias|ciphertext)"\s+"[^"]+"/g, algorithmId: "cloud-kms", assetType: "cloud-service", label: "AWS KMS (Terraform)", library: "Terraform aws_kms_key", kind: "config" },
  { id: "kms-azure-keyvault", pattern: /\b(?:azure\.keyvault|@azure\/keyvault-keys|com\.azure\.security\.keyvault|Azure\.Security\.KeyVault|KeyClient|CryptographyClient)\b/g, algorithmId: "cloud-kms", assetType: "cloud-service", label: "Azure Key Vault", library: "Azure Key Vault SDK", kind: "import" },
  { id: "kms-azure-url", pattern: /https:\/\/[\w-]+\.vault\.azure\.net[^\s"']*/g, algorithmId: "cloud-kms", assetType: "cloud-service", label: "Azure Key Vault", library: "Key Vault endpoint", kind: "config" },
  { id: "kms-azure-terraform", pattern: /resource\s+"azurerm_key_vault(?:_key)?"\s+"[^"]+"/g, algorithmId: "cloud-kms", assetType: "cloud-service", label: "Azure Key Vault (Terraform)", library: "Terraform azurerm_key_vault", kind: "config" },
  { id: "kms-gcp-sdk", pattern: /\b(?:google\.cloud\s+import\s+kms|google\.cloud\.kms|@google-cloud\/kms|KeyManagementServiceClient)\b/g, algorithmId: "cloud-kms", assetType: "cloud-service", label: "Google Cloud KMS", library: "GCP KMS SDK", kind: "import" },
  { id: "kms-gcp-resource", pattern: /projects\/[\w-]+\/locations\/[\w-]+\/keyRings\/[\w-]+\/cryptoKeys\/[\w-]+/g, algorithmId: "cloud-kms", assetType: "cloud-service", label: "Google Cloud KMS", library: "GCP KMS key resource", kind: "config" },
  { id: "kms-gcp-terraform", pattern: /resource\s+"google_kms_crypto_key(?:_version)?"\s+"[^"]+"/g, algorithmId: "cloud-kms", assetType: "cloud-service", label: "Google Cloud KMS (Terraform)", library: "Terraform google_kms_crypto_key", kind: "config" },
  { id: "kms-hashicorp-vault", pattern: /\b(?:hvac\.Client|@hashicorp\/vault|VaultTemplate|vault\.transit|transit\/(?:encrypt|decrypt))\b/g, algorithmId: "cloud-kms", assetType: "cloud-service", label: "HashiCorp Vault Transit", library: "HashiCorp Vault", kind: "import" },
]

/**
 * Standalone key-material signatures (F1).
 *
 * Two classes of evidence: PEM blocks that are key material rather than
 * certificates, and key-shaped literals hardcoded into source or config. Both
 * are catalogued as `type: "key"` artefacts in their own right, which the
 * problem statement names alongside algorithms and certificates.
 */
export const KEY_SIGNATURES: {
  id: string
  pattern: RegExp
  algorithmId: string
  label: string
  detail: string
  /** Capture group holding the literal value, for placeholder filtering. */
  valueGroup?: number
}[] = [
  { id: "key-pem-private", pattern: /-----BEGIN (RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP)? ?PRIVATE KEY-----/g, algorithmId: "key-material", label: "Private key", detail: "PEM private key block" },
  { id: "key-pem-public", pattern: /-----BEGIN (?:RSA |EC )?PUBLIC KEY-----/g, algorithmId: "key-material", label: "Public key", detail: "PEM public key block" },
  { id: "key-hardcoded-secret", pattern: /\b\w*(?:key|secret|passphrase|password|token)\w*\s*[:=]\s*(?:b|f|r|u)?["'`]([A-Za-z0-9+/=_.-]{16,})["'`]/gi, algorithmId: "hardcoded-key", label: "Hardcoded key material", detail: "key-shaped literal assigned in source", valueGroup: 1 },
  { id: "key-hex-literal", pattern: /\b\w*(?:key|iv|salt|nonce)\w*\s*[:=]\s*(?:b|f|r|u)?["'`]([0-9a-fA-F]{32,})["'`]/g, algorithmId: "hardcoded-key", label: "Hardcoded key material", detail: "hex key literal assigned in source", valueGroup: 1 },
]

/** Key/keystore file extensions that are artefacts in their own right (F1). */
export const KEY_FILE_TYPES: Record<string, { algorithmId: string; label: string; detail: string }> = {
  ".key": { algorithmId: "key-material", label: "Private key file", detail: "standalone key file" },
  ".pfx": { algorithmId: "keystore", label: "PKCS#12 keystore", detail: "PKCS#12 container (.pfx)" },
  ".p12": { algorithmId: "keystore", label: "PKCS#12 keystore", detail: "PKCS#12 container (.p12)" },
  ".jks": { algorithmId: "keystore", label: "Java keystore", detail: "Java KeyStore container (.jks)" },
  ".keystore": { algorithmId: "keystore", label: "Java keystore", detail: "Java KeyStore container (.keystore)" },
  ".bks": { algorithmId: "keystore", label: "BouncyCastle keystore", detail: "BouncyCastle keystore (.bks)" },
  ".p8": { algorithmId: "key-material", label: "PKCS#8 private key", detail: "PKCS#8 key file (.p8)" },
  ".pk8": { algorithmId: "key-material", label: "PKCS#8 private key", detail: "PKCS#8 key file (.pk8)" },
  ".asc": { algorithmId: "key-material", label: "PGP key", detail: "ASCII-armoured PGP key (.asc)" },
  ".gpg": { algorithmId: "key-material", label: "PGP key", detail: "PGP key material (.gpg)" },
}

/** Literals that look key-shaped but are obviously placeholders. */
export const KEY_PLACEHOLDERS =
  /^(?:x{8,}|0{8,}|your[-_]?|replace[-_]?|change[-_]?me|placeholder|example|dummy|sample|todo|insert[-_]|<.*>|\$\{)/i

/** Dependency manifest tokens → crypto library assets. */
export const DEPENDENCY_SIGNATURES: { token: RegExp; algorithmId: string; library: string }[] = [
  { token: /^\s*(pycryptodome|pycryptodomex|pycrypto)\b/i, algorithmId: "crypto-library", library: "pycryptodome" },
  { token: /^\s*cryptography\b/i, algorithmId: "crypto-library", library: "pyca/cryptography" },
  { token: /^\s*pyopenssl\b/i, algorithmId: "crypto-library", library: "pyOpenSSL" },
  { token: /^\s*pyjwt\b/i, algorithmId: "jwt", library: "PyJWT" },
  { token: /^\s*python-jose\b/i, algorithmId: "jwt", library: "python-jose" },
  { token: /^\s*paramiko\b/i, algorithmId: "ssh", library: "paramiko" },
  { token: /^\s*pynacl\b/i, algorithmId: "crypto-library", library: "PyNaCl" },
  { token: /^\s*bcrypt\b/i, algorithmId: "bcrypt", library: "bcrypt" },
  { token: /^\s*passlib\b/i, algorithmId: "pbkdf2", library: "passlib" },
  { token: /^\s*certifi\b/i, algorithmId: "x509-certificate", library: "certifi" },
  { token: /^\s*(liboqs-python|oqs|pqcrypto)\b/i, algorithmId: "ml-kem", library: "liboqs" },
  { token: /bcprov|bouncycastle/i, algorithmId: "crypto-library", library: "BouncyCastle" },
  { token: /jsonwebtoken/i, algorithmId: "jwt", library: "jsonwebtoken" },
  { token: /node-forge/i, algorithmId: "crypto-library", library: "node-forge" },
  { token: /^\s*jose\b/i, algorithmId: "jwt", library: "jose" },
]

/** Resolve free-text algorithm strings (e.g. `AES/CBC/PKCS5Padding`, `RS256`). */
export function resolveAlgorithmString(raw: string): string | undefined {
  const s = raw.toUpperCase()
  if (s.startsWith("RS") && /^RS(256|384|512)$/.test(s)) return "rsa-signature"
  if (/^PS(256|384|512)$/.test(s)) return "rsa-signature"
  if (/^ES(256|384|512)$/.test(s)) return "ecdsa"
  if (s === "EDDSA") return "ed25519"
  if (/^HS(256|384|512)$/.test(s)) return "hmac"
  if (s.includes("MD5")) return "md5"
  if (s.includes("SHA3")) return "sha3"
  if (s.includes("SHA-1") || s.includes("SHA1")) return "sha1"
  if (s.includes("SHA224") || s.includes("SHA256") || s.includes("SHA-256")) return "sha256"
  if (s.includes("SHA384") || s.includes("SHA512") || s.includes("SHA-512")) return "sha512"
  if (s.includes("TRIPLEDES") || s.includes("DESEDE") || s.includes("3DES")) return "3des"
  if (s.startsWith("DES")) return "des"
  if (s.includes("RC4") || s.includes("ARCFOUR")) return "rc4"
  if (s.includes("BLOWFISH")) return "blowfish"
  if (s.includes("CHACHA")) return "chacha20"
  if (s.includes("AES")) return "aes"
  if (s.includes("ECDH")) return "ecdh"
  if (s.includes("ECDSA")) return "ecdsa"
  if (s.includes("ED25519")) return "ed25519"
  if (s.includes("X25519")) return "x25519"
  if (s.includes("RSA")) return "rsa"
  if (s.includes("DSA")) return "dsa"
  if (s.includes("KYBER") || s.includes("ML-KEM") || s.includes("MLKEM")) return "ml-kem"
  if (s.includes("DILITHIUM") || s.includes("ML-DSA")) return "ml-dsa"
  if (s.includes("SPHINCS") || s.includes("SLH-DSA")) return "slh-dsa"
  if (s === "TLSV1" || s === "TLS" || s === "TLSV1.0") return "tls1.0"
  if (s === "TLSV1.1") return "tls1.1"
  if (s === "TLSV1.2") return "tls1.2"
  if (s === "TLSV1.3") return "tls1.3"
  if (s.includes("HMAC")) return "hmac"
  if (s.includes("PBKDF2")) return "pbkdf2"
  return undefined
}

/**
 * Key size implied by an algorithm name string (e.g. `AES-256-GCM`).
 *
 * JOSE/COSE identifiers (RS256, PS384, ES512, HS256) and `SHA1withRSA`-style
 * JCA names encode the *digest* size, not the key size, so they are excluded —
 * reporting "RSA-256" would be actively misleading.
 */
export function keySizeFromString(raw: string): number | undefined {
  const s = raw.toUpperCase()
  if (/^(RS|PS|ES|HS|EC|ED)(256|384|512)$/.test(s)) return undefined
  if (/WITH(RSA|ECDSA|DSA)/.test(s)) return undefined
  if (/^SHA-?\d+$/.test(s)) return undefined
  const m = raw.match(/(?:^|[^\d])(128|192|256|384|512|1024|2048|3072|4096|8192)(?:$|[^\d])/)
  return m ? Number(m[1]) : undefined
}

export function getAlgorithm(id: string): AlgorithmSpec {
  return ALGORITHMS[id] ?? ALGORITHMS["crypto-library"]
}

/**
 * F11 — cryptographic mode of operation from any string the scanner already
 * holds: a JCA transformation (`AES/GCM/NoPadding`), a Node cipher name
 * (`aes-256-cbc`), a cipher suite (`...AES256-GCM-SHA384`), or a filename
 * (`AESCBCEncryption.java`).
 *
 * Returns `undefined` rather than a guess when nothing is determinable; the
 * caller renders that as `Unspecified`.
 */
const MODE_TOKENS = "GCM-SIV|GCM|CBC|ECB|CTR|CCM|CFB8|CFB|OFB|XTS|OCB|EAX|SIV|KW|KWP"
const MODE_DELIMITED = new RegExp(`(?:^|[^A-Z0-9])(${MODE_TOKENS})(?:$|[^A-Z0-9])`, "i")
const MODE_GLUED = new RegExp(`(?:AES|DES|DESEDE|TRIPLEDES|RC2|CAMELLIA|SEED|ARIA)(?:\\d{3})?(${MODE_TOKENS})`, "i")

export function modeFromString(raw: string): string | undefined {
  if (!raw) return undefined
  const delimited = raw.match(MODE_DELIMITED)
  if (delimited) return delimited[1].toUpperCase()
  const glued = raw.match(MODE_GLUED)
  if (glued) return glued[1].toUpperCase()
  // Stream ciphers have no mode of operation; say so explicitly instead of
  // leaving the field blank and implying the scanner missed it.
  if (/CHACHA20|POLY1305|ARCFOUR|\bRC4\b/i.test(raw)) return "Stream"
  return undefined
}

export const SIGNATURE_DB_STATS = {
  algorithms: Object.keys(ALGORITHMS).length,
  pythonImports: PYTHON_IMPORTS.length,
  pythonCalls: PYTHON_CALLS.length,
  regexSignatures: REGEX_SIGNATURES.length,
  configSignatures: CONFIG_SIGNATURES.length,
  dependencySignatures: DEPENDENCY_SIGNATURES.length,
  referenceSignatures: HSM_SIGNATURES.length + CLOUD_SIGNATURES.length,
  keySignatures: KEY_SIGNATURES.length,
  get total() {
    return (
      this.pythonImports +
      this.pythonCalls +
      this.regexSignatures +
      this.configSignatures +
      this.dependencySignatures +
      this.referenceSignatures +
      this.keySignatures
    )
  },
}
