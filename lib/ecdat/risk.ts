/**
 * ECDAT quantum risk engine — Step 4 of the pipeline.
 *
 * Mosca's inequality (Mosca, 2015): if  X + Y > Z  you are already too late.
 *
 *   X = how long the data must stay confidential (shelf-life)
 *   Y = how long the migration of this asset takes
 *   Z = years until a Cryptographically Relevant Quantum Computer (CRQC)
 *
 * Z is an assumption, not a fact, so ECDAT (a) ships a cited default and
 * (b) makes it adjustable in the dashboard rather than burying it in code.
 *
 * Cited default for Z: NSA CNSA 2.0 requires national-security systems to be
 * PQC-exclusive by 2033 (with most classes transitioning from 2030), and the
 * White House NSM-10 / NIST IR 8547 timelines deprecate RSA/ECC by 2030 and
 * disallow them by 2035. ECDAT therefore defaults the CRQC horizon to 2033.
 *
 * Vulnerability and urgency are reported as two independent signals, exactly as
 * the PRD requires: an RSA key is quantum-vulnerable even if its Mosca margin
 * is comfortable, and an MD5 hash is urgent for reasons that have nothing to do
 * with quantum computing.
 */

import { getAlgorithm } from "./signatures"
import type { CryptoAsset, MoscaParams, MoscaResult, RiskTier } from "./types"

export const DEFAULT_CRQC_YEAR = 2033

export const DEFAULT_MOSCA_PARAMS: MoscaParams = {
  z: DEFAULT_CRQC_YEAR - new Date().getFullYear(),
  xMultiplier: 1,
}

/**
 * Y — migration time in years, by the kind of artefact being replaced.
 * Rotating a certificate is a sprint; replacing a protocol wired through a
 * codebase and its partners is a multi-year programme.
 */
export const MIGRATION_TIME: Record<string, { years: number; label: string }> = {
  certificate: { years: 0.5, label: "certificate reissue — weeks to months" },
  dependency: { years: 1, label: "library upgrade across build pipeline" },
  import: { years: 1.5, label: "library swap plus regression testing" },
  config: { years: 1.5, label: "configuration + fleet rollout" },
  call: { years: 2.5, label: "code-level algorithm replacement" },
  "string-literal": { years: 2, label: "embedded algorithm identifier" },
  // F1 — a key or keystore is re-issued and redistributed, not rewritten.
  "key-file": { years: 1, label: "key regeneration and redistribution" },
  // F9 — a packaged artifact may not have source available to this team.
  binary: { years: 3, label: "repackage a shipped binary artifact" },
  // F10 — rebuild the image, revalidate it, then roll the fleet.
  container: { years: 3.5, label: "image rebuild plus fleet redeployment" },
}

const PROTOCOL_MIGRATION_YEARS = 3.5

export function migrationTime(asset: CryptoAsset, params: MoscaParams): { y: number; label: string } {
  if (params.yOverride !== undefined) {
    return { y: params.yOverride, label: "operator override" }
  }

  const base = MIGRATION_TIME[asset.evidence] ?? { years: 2, label: "generic code change" }
  let y = base.years
  const notes: string[] = [base.label]

  if (asset.type === "protocol") {
    y = Math.max(y, PROTOCOL_MIGRATION_YEARS)
    notes.push("protocol change requires counterparty coordination")
  }
  if (asset.primitive === "key-agreement") {
    y += 0.5
    notes.push("key agreement touches every peer")
  }
  if (asset.classification.businessCriticality === "High") {
    y *= 1.25
    notes.push("high-criticality change control")
  } else if (asset.classification.businessCriticality === "Low") {
    y *= 0.75
  }
  // Blast radius: more call sites means a longer migration, sub-linearly.
  if (asset.occurrences > 1) {
    y += Math.min(1.5, Math.log2(asset.occurrences) * 0.25)
    notes.push(`${asset.occurrences} occurrences in this file`)
  }

  return { y: Math.round(y * 10) / 10, label: notes.join("; ") }
}

function tierFromMargin(margin: number): RiskTier {
  if (margin > 0) return "Critical"
  if (margin > -2) return "High"
  if (margin > -5) return "Medium"
  return "Low"
}

export const TIER_ORDER: RiskTier[] = ["Critical", "High", "Medium", "Low"]

export function scoreAsset(asset: CryptoAsset, params: MoscaParams): { mosca: MoscaResult; riskTier: RiskTier } {
  const spec = getAlgorithm(asset.algorithmId)
  const x = Math.round(asset.classification.dataLifetime * params.xMultiplier * 10) / 10
  const { y, label } = migrationTime(asset, params)
  const z = params.z
  const margin = Math.round((x + y - z) * 10) / 10

  let tier = tierFromMargin(margin)
  const reasons: string[] = [
    `X=${x}y (${asset.classification.businessCriticality} criticality data) + Y=${y}y (${label}) ${
      margin > 0 ? ">" : "<="
    } Z=${z}y to CRQC`,
  ]

  if (!spec.quantumVulnerable) {
    // Quantum-safe primitives are not on the Mosca clock at all.
    if (spec.groverWeakened && (asset.keySize ?? 0) < 256) {
      tier = tier === "Critical" || tier === "High" ? "Medium" : tier
      reasons.push("Grover only halves effective strength — raise key/digest size to >=256 bits rather than replacing")
    } else {
      tier = "Low"
      reasons.push("quantum-safe primitive — Mosca urgency does not apply")
    }
  }

  if (spec.classicallyBroken) {
    // Already broken today outranks any future-dated quantum concern.
    tier = tier === "Critical" ? "Critical" : "High"
    reasons.push("already broken by classical attacks — remediate independently of PQC timeline")
  }

  if (spec.family === "PQC") {
    tier = "Low"
    reasons.push("already a NIST PQC standard — no migration required")
  }

  return {
    mosca: { x, y, z, margin, tier, explanation: reasons.join(". ") },
    riskTier: tier,
  }
}

export function scoreAssets(assets: CryptoAsset[], params: MoscaParams): CryptoAsset[] {
  return assets.map((asset) => {
    const { mosca, riskTier } = scoreAsset(asset, params)
    return { ...asset, mosca, riskTier }
  })
}

export function tierCounts(assets: CryptoAsset[]): Record<RiskTier, number> {
  const counts: Record<RiskTier, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 }
  for (const a of assets) counts[a.riskTier]++
  return counts
}

/**
 * Aggregate quantum-readiness score (0-100). Weighted by risk tier and
 * business criticality so a Critical finding in /payments hurts more than a
 * Medium finding in /scripts.
 */
export function readinessScore(assets: CryptoAsset[]): number {
  if (!assets.length) return 100
  const tierWeight: Record<RiskTier, number> = { Critical: 10, High: 6, Medium: 2.5, Low: 0.4 }
  const critWeight = { High: 1.4, Medium: 1, Low: 0.6 }
  let penalty = 0
  for (const a of assets) {
    penalty += tierWeight[a.riskTier] * critWeight[a.classification.businessCriticality]
  }
  const normalized = penalty / assets.length
  return Math.max(0, Math.min(100, Math.round(100 - normalized * 9)))
}
