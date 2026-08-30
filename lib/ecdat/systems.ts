/**
 * ECDAT system rollup (F6).
 *
 * The per-asset explorer answers "which line of code is a problem". An owner
 * asks a different question: "which of my systems is a problem". This module is
 * pure aggregation over the assets the pipeline already produced — no new
 * detection, no new scoring. The grouping key is `asset.systemKey`, derived in
 * `classification.ts` from the source path (build scaffolding and Java package
 * prefixes stripped), so a Maven project groups as `encryption/aes` rather than
 * `src/main/java/com`.
 *
 * The group's tier is the worst tier inside it, deliberately: a system with one
 * Critical asset is a Critical system, and the count breakdown carries the
 * volume alongside it.
 */

import { TIER_ORDER, readinessScore } from "./risk"
import type { AssetType, CryptoAsset, Facing, RiskTier, SystemRollup } from "./types"

const TIER_RANK: Record<RiskTier, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 }

/** Human-readable group name: `encryption/aes` → `encryption / aes`. */
function displayName(key: string): string {
  if (key === "(root)") return "Repository root"
  return key.split("/").join(" / ")
}

function facingOf(members: CryptoAsset[]): Facing {
  let internal = false
  let external = false
  for (const m of members) {
    if (m.classification.facing === "External") external = true
    else if (m.classification.facing === "Internal") internal = true
    else return "Mixed"
  }
  if (external && internal) return "Mixed"
  if (external) return "External"
  if (internal) return "Internal"
  return "Mixed"
}

export function buildSystems(assets: CryptoAsset[]): SystemRollup[] {
  const groups = new Map<string, CryptoAsset[]>()
  for (const asset of assets) {
    const key = asset.systemKey || "(root)"
    const bucket = groups.get(key)
    if (bucket) bucket.push(asset)
    else groups.set(key, [asset])
  }

  const rollups: SystemRollup[] = []

  for (const [key, members] of groups) {
    const counts: Record<RiskTier, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 }
    const files = new Set<string>()
    const types = new Set<AssetType>()
    let occurrences = 0
    let quantumVulnerable = 0
    let sensitiveData = 0
    let worstMargin = Number.NEGATIVE_INFINITY

    for (const asset of members) {
      counts[asset.riskTier]++
      files.add(asset.file)
      types.add(asset.type)
      occurrences += asset.occurrences
      if (asset.quantumVulnerable) quantumVulnerable++
      if (asset.classification.sensitiveData) sensitiveData++
      if (asset.mosca.margin > worstMargin) worstMargin = asset.mosca.margin
    }

    const tier = TIER_ORDER.find((t) => counts[t] > 0) ?? "Low"

    rollups.push({
      key,
      name: displayName(key),
      tier,
      counts,
      assets: members.length,
      occurrences,
      files: files.size,
      quantumVulnerable,
      sensitiveData,
      facing: facingOf(members),
      worstMargin: worstMargin === Number.NEGATIVE_INFINITY ? 0 : worstMargin,
      readiness: readinessScore(members),
      types: [...types].sort(),
      members: [...members].sort(
        (a, b) => TIER_RANK[a.riskTier] - TIER_RANK[b.riskTier] || b.mosca.margin - a.mosca.margin,
      ),
    })
  }

  return rollups.sort(
    (a, b) =>
      TIER_RANK[a.tier] - TIER_RANK[b.tier] ||
      b.counts[b.tier] - a.counts[a.tier] ||
      b.worstMargin - a.worstMargin ||
      a.name.localeCompare(b.name),
  )
}

/** Portfolio-level summary shown above the group table. */
export function systemTotals(systems: SystemRollup[]) {
  const counts: Record<RiskTier, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 }
  for (const system of systems) counts[system.tier]++
  return {
    systems: systems.length,
    counts,
    external: systems.filter((s) => s.facing === "External").length,
    sensitive: systems.filter((s) => s.sensitiveData > 0).length,
    worstReadiness: systems.length ? Math.min(...systems.map((s) => s.readiness)) : 100,
  }
}
