/**
 * ECDAT — core domain types.
 *
 * The asset shape is deliberately aligned with the CycloneDX 1.6 / ECMA-424
 * `cryptographic-asset` component model so the CBOM export is a projection of
 * these objects rather than a separate hand-written document.
 */

export type CryptoPrimitive =
  | "signature"
  | "key-agreement"
  | "key-encapsulation"
  | "public-key-encryption"
  | "encryption"
  | "hash"
  | "mac"
  | "kdf"
  | "drbg"
  | "protocol"
  | "other"

export type AssetType =
  | "algorithm"
  | "certificate"
  | "protocol"
  | "library"
  | "related-crypto-material"
  /** F1 — standalone key material (keystores, private key files, hardcoded keys). */
  | "key"
  /** F3 — reference to a hardware security module (detection only, never a live query). */
  | "hardware-module"
  /** F4 — reference to a cloud key-management service (detection only). */
  | "cloud-service"

export type EvidenceKind =
  | "import"
  | "call"
  | "certificate"
  | "config"
  | "dependency"
  | "string-literal"
  /** F1 — a standalone key/keystore file. */
  | "key-file"
  /** F9 — JAR metadata inspection. */
  | "binary"
  /** F10 — files extracted out of a container image / Dockerfile. */
  | "container"

export type RiskTier = "Critical" | "High" | "Medium" | "Low"

export type Criticality = "High" | "Medium" | "Low"

/** F5 — whether the scanned asset sits on an internal or an external boundary. */
export type Facing = "Internal" | "External" | "Mixed"

export type Language =
  | "python"
  | "java"
  | "javascript"
  | "go"
  | "csharp"
  | "config"
  | "manifest"
  | "certificate"
  | "key"
  | "binary"
  | "unknown"

/** A single raw hit produced by a scanner before classification. */
export interface RawFinding {
  file: string
  line: number
  kind: EvidenceKind
  /** Verbatim matched token, e.g. `hashlib.md5` or `javax.crypto.Cipher`. */
  matched: string
  /** Source line (trimmed) used as evidence in the UI + SARIF. */
  snippet: string
  language: Language
  /** Resolved algorithm id from the signature DB. */
  algorithmId: string
  /** Key size when statically recoverable (e.g. `RSA.generate(2048)`). */
  keySize?: number
  /** F11 — mode of operation (GCM, CBC, ECB, CTR…) when recoverable. */
  mode?: string
  /** Extra detail, e.g. certificate subject or config directive. */
  detail?: string
  /** Scanner confidence: AST-grade resolution vs. lexical/regex fallback. */
  confidence: "high" | "medium" | "low"
  detector: string
  /**
   * Overrides the asset type inferred from the algorithm spec. Used by the
   * detectors that catalogue non-algorithm artefacts (F1 keys, F2 protocols,
   * F3 hardware modules, F4 cloud services).
   */
  assetType?: AssetType
  /** Overrides the display name, e.g. `TLS 1.2 — ECDHE-RSA-AES256-GCM-SHA384`. */
  label?: string
  /**
   * U5 — scope caption carried through to the UI verbatim, e.g. "Detected via
   * binary metadata inspection". Set by the detectors whose scope is narrower
   * than a reader would assume; otherwise derived from the evidence kind.
   */
  scopeNote?: string
}

export interface AlgorithmSpec {
  id: string
  name: string
  /** Algorithm family used for recommendation lookup. */
  family: string
  primitive: CryptoPrimitive
  assetType: AssetType
  defaultKeySize?: number
  /** Broken by Shor's algorithm — a quantum computer defeats it outright. */
  quantumVulnerable: boolean
  /** Only weakened by Grover (effective strength halved). */
  groverWeakened?: boolean
  /** Already broken/deprecated classically (MD5, SHA-1, DES, RC4, TLS 1.0). */
  classicallyBroken?: boolean
  nistStatus: string
  /** Default years the protected data must stay confidential (Mosca X). */
  defaultDataLifetime: number
  reference?: string
  /**
   * F8 — static performance characteristic surfaced with the recommendation so
   * the latency/size trade-off is visible instead of implied.
   */
  latencyNote?: string
  /** F8 — coarse ranking used to phrase the trade-off ("larger handshake"). */
  latencyProfile?: "light" | "moderate" | "heavy"
}

export interface Classification {
  businessCriticality: Criticality
  /** Mosca X — years the data must remain confidential. */
  dataLifetime: number
  /** Reason string shown in the UI so heuristics are auditable. */
  rationale: string
  /** True when a human overrode the heuristic in the dashboard. */
  overridden?: boolean
  /**
   * F7 — does this crypto protect a sensitive data category (PII, payment,
   * health)? Independent of business criticality.
   */
  sensitiveData: boolean
  /** Why the sensitive-data flag was set, so the heuristic stays auditable. */
  sensitiveDataRationale: string
  /** F5 — internal vs. external-facing classification. */
  facing: Facing
  /** How `facing` was decided: scan-level default, path heuristic, or a human. */
  facingSource: "scan" | "path" | "override"
}

export interface MoscaResult {
  x: number
  y: number
  z: number
  /** (X + Y) - Z. Positive means the window is already blown. */
  margin: number
  tier: RiskTier
  explanation: string
}

export interface Recommendation {
  /** Primary NIST replacement, e.g. `ML-KEM-768 (FIPS 203)`. */
  primary: string
  standard: string
  /** Hybrid transition option when latency/compat risk is high. */
  hybrid?: string
  conservative?: string
  notes: string
  /** Rough migration complexity driver, feeds the roadmap effort model. */
  complexity: "low" | "medium" | "high"
  /** F8 — one-line performance/latency trade-off for the chosen target. */
  performanceNote?: string
  /** F8 — true when the hybrid option was preferred over pure PQC. */
  latencyWeighted?: boolean
}

export interface CryptoAsset {
  /** Stable id: sha1-ish hash of algorithm + location. */
  id: string
  type: AssetType
  name: string
  algorithmId: string
  family: string
  primitive: CryptoPrimitive
  keySize?: number
  /** F11 — mode of operation; `"Unspecified"` when not determinable. */
  mode: string
  location: string
  file: string
  line: number
  evidence: EvidenceKind
  snippet: string
  language: Language
  confidence: "high" | "medium" | "low"
  detector: string
  occurrences: number
  /** Every location this asset was seen at (deduped). */
  locations: string[]
  classification: Classification
  quantumVulnerable: boolean
  groverWeakened: boolean
  classicallyBroken: boolean
  nistStatus: string
  mosca: MoscaResult
  riskTier: RiskTier
  recommendation?: Recommendation
  detail?: string
  /** F6 — grouping key this asset rolls up into (top-level source directory). */
  systemKey: string
  /**
   * U5 — set on findings produced by the lighter-weight detection modes so the
   * UI can never present them as full source-level evidence.
   */
  scopeNote?: string
}

/** F6 — one rolled-up application/system row. */
export interface SystemRollup {
  key: string
  name: string
  /** Highest risk tier present in the group. */
  tier: RiskTier
  counts: Record<RiskTier, number>
  assets: number
  occurrences: number
  files: number
  quantumVulnerable: number
  sensitiveData: number
  facing: Facing
  /** Worst (largest) Mosca margin in the group. */
  worstMargin: number
  readiness: number
  /** Distinct artefact types present, for the group badge row. */
  types: AssetType[]
  /** Assets sorted worst-first, for the drill-down. */
  members: CryptoAsset[]
}

export interface MoscaParams {
  /** Years until a Cryptographically Relevant Quantum Computer exists. */
  z: number
  /** Global override of migration time in years; undefined = per-type table. */
  yOverride?: number
  /** Multiplier applied to inferred data lifetime. */
  xMultiplier: number
}

export interface ScanTarget {
  path: string
  content: string
  /** Byte length, used for throughput metrics. */
  size: number
  sha: string
}

export interface ScanMetrics
{
  filesDiscovered: number
  filesScanned: number
  filesSkipped: number
  filesFromCache: number
  bytesScanned: number
  findings: number
  durationMs: number
  fetchMs: number
  analyzeMs: number
  filesPerSecond: number
  kbPerSecond: number
  parseErrors: { file: string; error: string }[]
  languageBreakdown: Record<string, number>
}

export interface ScanResult {
  scanId: string
  source: {
    kind: "github" | "upload" | "demo" | "container"
    label: string
    ref?: string
    url?: string
  }
  startedAt: string
  assets: CryptoAsset[]
  metrics: ScanMetrics
  moscaParams: MoscaParams
  /** F5 — the facing declared for this scan (default `Mixed`). */
  facing: Facing
  /** Files that were walked, for the dependency graph + coverage panel. */
  scannedFiles: { path: string; language: Language; findings: number; sha: string }[]
  warnings: string[]
}
