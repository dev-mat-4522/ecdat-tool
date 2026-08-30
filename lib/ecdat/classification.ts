/**
 * ECDAT classification layer — Step 3 of the pipeline.
 *
 * Turns raw findings into CycloneDX-shaped cryptographic assets and assigns
 * the two inputs the risk engine needs but static analysis cannot read from
 * code: business criticality and data shelf-life. Both are heuristics with an
 * explicit, human-readable rationale, and both are overridable in the
 * dashboard — the tool never pretends these are measured facts.
 */

import { getAlgorithm, modeFromString } from "./signatures"
import type { AssetType, Classification, Criticality, CryptoAsset, Facing, RawFinding } from "./types"

interface PathRule {
  pattern: RegExp
  criticality: Criticality
  /** Years the data protected here is expected to stay sensitive. */
  lifetime: number
  label: string
}

/**
 * Path heuristics, ordered most-specific first. Lifetimes follow common
 * regulatory retention floors (health/financial records outlive session data
 * by an order of magnitude), which is exactly the spread Mosca's X captures.
 */
export const PATH_RULES: PathRule[] = [
  { pattern: /(^|\/)(health|medical|patient|phi|ehr)(\/|_|-)/i, criticality: "High", lifetime: 25, label: "health records (long statutory retention)" },
  { pattern: /(^|\/)(payment|billing|invoice|pci|card|wallet|ledger)/i, criticality: "High", lifetime: 15, label: "payment / financial data" },
  { pattern: /(^|\/)(kyc|identity|passport|govid|aadhaar)/i, criticality: "High", lifetime: 20, label: "identity documents" },
  { pattern: /(^|\/)(auth|authn|authz|login|session|iam|oauth|sso|token)/i, criticality: "High", lifetime: 12, label: "authentication path" },
  { pattern: /(^|\/)(key|kms|hsm|secret|vault|crypto|pki|cert)/i, criticality: "High", lifetime: 15, label: "key management material" },
  { pattern: /(^|\/)(user|account|profile|customer|pii)/i, criticality: "High", lifetime: 10, label: "personal data" },
  { pattern: /(^|\/)(api|service|server|gateway|controller|handler|route)/i, criticality: "Medium", lifetime: 8, label: "service boundary" },
  { pattern: /(^|\/)(db|database|storage|repo|persistence|model|migration)/i, criticality: "Medium", lifetime: 10, label: "persistence layer" },
  { pattern: /(^|\/)(infra|deploy|ops|config|helm|k8s|terraform|nginx|ssh)/i, criticality: "Medium", lifetime: 12, label: "infrastructure configuration" },
  { pattern: /(^|\/)(internal|admin|backoffice)/i, criticality: "Medium", lifetime: 8, label: "internal tooling" },
  { pattern: /(^|\/)(test|tests|spec|fixture|mock|example|sample|demo|docs|benchmark)/i, criticality: "Low", lifetime: 1, label: "test / example code (not production data)" },
  { pattern: /(^|\/)(script|tool|util|cli)/i, criticality: "Low", lifetime: 3, label: "developer tooling" },
]

const CRITICALITY_RANK: Record<Criticality, number> = { High: 3, Medium: 2, Low: 1 }

export function classifyPath(file: string): { criticality: Criticality; lifetime: number; label: string } {
  const normalized = `/${file.replace(/\\/g, "/").toLowerCase()}`
  for (const rule of PATH_RULES) {
    if (rule.pattern.test(normalized)) {
      return { criticality: rule.criticality, lifetime: rule.lifetime, label: rule.label }
    }
  }
  return { criticality: "Medium", lifetime: 7, label: "no path signal — organisation default applied" }
}

/**
 * F7 — sensitive-data heuristics. Deliberately kept separate from the
 * criticality rules above: "this code is important to the business" and "this
 * code protects regulated personal data" are different questions, and a judge
 * (or an auditor) needs to filter on the second one directly.
 */
export const SENSITIVE_DATA_RULES: { pattern: RegExp; label: string }[] = [
  { pattern: /(^|\/)(payment|billing|invoice|pci|card|wallet|ledger|settlement|acquirer|merchant)/i, label: "payment data (PCI DSS)" },
  { pattern: /(^|\/)(health|medical|patient|phi|ehr)/i, label: "health data (PHI)" },
  { pattern: /(^|\/)(pii|personal|user|users|account|profile|customer|subscriber)/i, label: "personal data (PII)" },
  { pattern: /(^|\/)(kyc|identity|passport|govid|aadhaar|ssn|nid)/i, label: "identity documents" },
  { pattern: /(^|\/)(auth|authn|login|session|credential|password|secret|vault|token)/i, label: "credentials / authentication secrets" },
  { pattern: /(^|\/)(key|kms|hsm|pki|cert|keystore)/i, label: "key material" },
]

const NON_PRODUCTION = /(^|\/)(test|tests|spec|fixture|mock|example|sample|demo|docs|benchmark)(\/|$)/i

export function classifySensitiveData(file: string): { sensitive: boolean; rationale: string } {
  const normalized = `/${file.replace(/\\/g, "/").toLowerCase()}`
  const hit = SENSITIVE_DATA_RULES.find((rule) => rule.pattern.test(normalized))
  if (!hit) return { sensitive: false, rationale: "no sensitive-data signal in path" }
  if (NON_PRODUCTION.test(normalized)) {
    return { sensitive: false, rationale: `${hit.label} pattern matched, but path is test/example code` }
  }
  return { sensitive: true, rationale: hit.label }
}

/** F5 — path signals for the internal/external boundary. */
const EXTERNAL_PATH = /(^|\/)(public|external|edge|gateway|ingress|web|www|frontend|client|api|proxy|cdn|checkout|storefront)(\/|$)/i
const INTERNAL_PATH = /(^|\/)(internal|admin|backoffice|intranet|batch|worker|cron|job|ops|infra|migration|scripts?)(\/|$)/i

export function classifyFacing(file: string, scanFacing: Facing = "Mixed"): { facing: Facing; source: "scan" | "path" } {
  // An explicit declaration on the scan configuration always wins — the person
  // running the scan knows the deployment boundary; a path never does.
  if (scanFacing === "Internal" || scanFacing === "External") return { facing: scanFacing, source: "scan" }
  const normalized = `/${file.replace(/\\/g, "/").toLowerCase()}`
  if (EXTERNAL_PATH.test(normalized)) return { facing: "External", source: "path" }
  if (INTERNAL_PATH.test(normalized)) return { facing: "Internal", source: "path" }
  return { facing: "Mixed", source: "scan" }
}

/**
 * F6 — grouping key. Strips build scaffolding and Java-style package preambles
 * so `src/main/java/com/mastercard/developer/encryption/aes/AESEncryption.java`
 * rolls up as `encryption/aes` rather than as its full path.
 */
const SCAFFOLD_SEGMENTS = new Set([
  "src", "main", "test", "tests", "__tests__", "spec", "java", "kotlin", "scala",
  "resources", "target", "out", "dist", "build", "source", "sources",
])
const PACKAGE_TLD = /^(com|org|net|io|dev|edu|gov|co|in|uk|de|fr|us|me)$/

export function systemKeyFor(file: string): string {
  const parts = file.replace(/\\/g, "/").split("/").filter(Boolean)
  let segments = parts.slice(0, -1).map((s) => s.toLowerCase())
  while (segments.length && SCAFFOLD_SEGMENTS.has(segments[0])) segments = segments.slice(1)
  if (segments.length > 1 && PACKAGE_TLD.test(segments[0])) {
    segments = segments.slice(1)
    let dropped = 1
    while (dropped < 3 && segments.length > 1) {
      segments = segments.slice(1)
      dropped++
    }
  }
  if (!segments.length) return "(root)"
  return segments.slice(0, 3).join("/")
}

/** F11 — mode of operation, resolved from whatever evidence the scanner captured. */
export function resolveMode(finding: RawFinding, primitive: string): string {
  if (finding.mode) return finding.mode
  if (primitive !== "encryption" && primitive !== "public-key-encryption") return "Unspecified"
  return (
    modeFromString(finding.matched) ??
    modeFromString(finding.snippet) ??
    modeFromString(finding.file.replace(/\\/g, "/").split("/").pop() ?? "") ??
    "Unspecified"
  )
}

export function classifyFinding(finding: RawFinding, scanFacing: Facing = "Mixed"): Classification {
  const spec = getAlgorithm(finding.algorithmId)
  const path = classifyPath(finding.file)

  // Data lifetime: the longer of the path signal and the algorithm default,
  // because a short-lived path cannot shorten the shelf-life of, say, a
  // 20-year archival key-agreement secret.
  let lifetime = Math.max(path.lifetime, Math.round(spec.defaultDataLifetime * 0.6))
  const notes = [path.label]

  // Certificates carry their own authoritative lifetime when we parsed one.
  const validityMatch = finding.detail?.match(/([\d.]+)y remaining validity/)
  if (validityMatch) {
    lifetime = Math.max(1, Math.round(Number(validityMatch[1])))
    notes.push(`certificate validity window (${validityMatch[1]}y remaining)`)
  }

  // Key-agreement material is the classic "harvest now, decrypt later" target:
  // recorded traffic stays decryptable for as long as the payload matters.
  if (spec.primitive === "key-agreement" || spec.primitive === "key-encapsulation") {
    lifetime = Math.max(lifetime, 12)
    notes.push("key agreement — exposed to harvest-now-decrypt-later")
  }

  // Ephemeral signature use (JWT) does not need long confidentiality.
  if (spec.family === "JWT") {
    lifetime = Math.min(lifetime, 3)
    notes.push("short-lived token signing")
  }

  let criticality = path.criticality
  if (finding.kind === "dependency" && criticality === "High") criticality = "Medium"
  if (spec.classicallyBroken && CRITICALITY_RANK[criticality] < 3) {
    criticality = criticality === "Low" ? "Medium" : "High"
    notes.push("escalated: algorithm already broken classically")
  }

  const sensitive = classifySensitiveData(finding.file)
  const facing = classifyFacing(finding.file, scanFacing)

  return {
    businessCriticality: criticality,
    dataLifetime: lifetime,
    rationale: notes.join("; "),
    sensitiveData: sensitive.sensitive,
    sensitiveDataRationale: sensitive.rationale,
    facing: facing.facing,
    facingSource: facing.source,
  }
}

/** Deterministic short id so re-scans produce stable asset identities. */
export function assetId(parts: string[]): string {
  const input = parts.join("|")
  let h1 = 0x811c9dc5
  let h2 = 0x1000193
  for (let i = 0; i < input.length; i++) {
    h1 ^= input.charCodeAt(i)
    h1 = Math.imul(h1, 0x01000193) >>> 0
    h2 = (Math.imul(h2 ^ input.charCodeAt(i), 0x85ebca6b) >>> 0) ^ (h2 >>> 13)
  }
  return `${h1.toString(16).padStart(8, "0")}${(h2 >>> 0).toString(16).padStart(8, "0")}`
}

/** U5 — captions for the lighter-weight detection modes. */
const SCOPE_NOTES: Partial<Record<AssetType | string, string>> = {
  "hardware-module": "Reference detected — not a live inventory query",
  "cloud-service": "Reference detected — not a live inventory query",
}
const EVIDENCE_SCOPE_NOTES: Partial<Record<string, string>> = {
  binary: "Detected via binary metadata inspection",
  container: "Detected via container metadata inspection",
}

export function scopeNoteFor(type: AssetType, evidence: string): string | undefined {
  return EVIDENCE_SCOPE_NOTES[evidence] ?? SCOPE_NOTES[type]
}

/**
 * Findings -> assets. Identical algorithm + file are merged into one asset
 * with an occurrence count so a loop that hashes 40 times does not inflate the
 * inventory (a real complaint about first-generation CBOM tools).
 */
export function buildAssets(findings: RawFinding[], options: { facing?: Facing } = {}): CryptoAsset[] {
  const byKey = new Map<string, CryptoAsset>()
  const scanFacing = options.facing ?? "Mixed"

  for (const finding of findings) {
    const spec = getAlgorithm(finding.algorithmId)
    const keySize = finding.keySize ?? spec.defaultKeySize
    const type = finding.assetType ?? spec.assetType
    const mode = resolveMode(finding, spec.primitive)
    const baseName =
      keySize && type === "algorithm" && spec.family !== "RNG" && spec.family !== "LIBRARY"
        ? `${spec.name}-${keySize}`
        : spec.name
    const displayName = finding.label ?? (mode !== "Unspecified" ? `${baseName}-${mode}` : baseName)
    // `mode` joins the identity key: AES-GCM and AES-CBC in one file are two
    // different findings with two different remediation stories.
    const key = `${finding.algorithmId}|${keySize ?? "na"}|${mode}|${type}|${finding.file}|${finding.kind}`
    const location = `${finding.file}:${finding.line}`

    const existing = byKey.get(key)
    if (existing) {
      existing.occurrences++
      if (!existing.locations.includes(location)) existing.locations.push(location)
      if (finding.confidence === "high") existing.confidence = "high"
      continue
    }

    const classification = classifyFinding(finding, scanFacing)
    byKey.set(key, {
      id: assetId([finding.algorithmId, String(keySize ?? ""), mode, type, finding.file, finding.kind]),
      type,
      name: displayName,
      algorithmId: spec.id,
      family: spec.family,
      primitive: spec.primitive,
      keySize,
      mode,
      location,
      file: finding.file,
      line: finding.line,
      evidence: finding.kind,
      snippet: finding.snippet,
      language: finding.language,
      confidence: finding.confidence,
      detector: finding.detector,
      occurrences: 1,
      locations: [location],
      classification,
      quantumVulnerable: spec.quantumVulnerable,
      groverWeakened: Boolean(spec.groverWeakened),
      classicallyBroken: Boolean(spec.classicallyBroken),
      nistStatus: spec.nistStatus,
      detail: finding.detail,
      systemKey: systemKeyFor(finding.file),
      scopeNote: finding.scopeNote ?? scopeNoteFor(type, finding.kind),
      // Filled in by the risk engine.
      mosca: { x: 0, y: 0, z: 0, margin: 0, tier: "Low", explanation: "" },
      riskTier: "Low",
    })
  }

  return [...byKey.values()]
}
