/**
 * Migration roadmap generator.
 *
 * Groups assets into remediation work items, orders them by Mosca urgency, and
 * attaches a transparent effort estimate. The effort model is deliberately
 * simple and fully disclosed — an engineer can audit every multiplier — because
 * a black-box cost number is worse than no number.
 */

import type { CryptoAsset, RiskTier } from "./types"

/** Base engineer-days per remediation type. */
const BASE_DAYS: Record<string, number> = {
  certificate: 2,
  dependency: 3,
  import: 4,
  config: 3,
  call: 6,
  "string-literal": 4,
  "key-file": 3,
  binary: 8,
  container: 6,
}

const COMPLEXITY_MULTIPLIER = { low: 1, medium: 1.8, high: 3 }
const CRITICALITY_MULTIPLIER = { Low: 0.8, Medium: 1, High: 1.4 }

export type Wave = "Wave 1 — Immediate (0-6 months)" | "Wave 2 — Near term (6-18 months)" | "Wave 3 — Planned (18-36 months)" | "Wave 4 — Monitor"

export interface RoadmapItem {
  key: string
  title: string
  wave: Wave
  riskTier: RiskTier
  algorithm: string
  family: string
  primitive: string
  target: string
  standard: string
  hybrid?: string
  /** U6 — one-line size/latency consequence of the target algorithm. */
  performanceNote?: string
  files: string[]
  assetIds: string[]
  occurrences: number
  worstMargin: number
  effortDays: number
  complexity: "low" | "medium" | "high"
  rationale: string
  actions: string[]
}

function waveFor(tier: RiskTier, classicallyBroken: boolean): Wave {
  if (classicallyBroken) return "Wave 1 — Immediate (0-6 months)"
  switch (tier) {
    case "Critical":
      return "Wave 1 — Immediate (0-6 months)"
    case "High":
      return "Wave 2 — Near term (6-18 months)"
    case "Medium":
      return "Wave 3 — Planned (18-36 months)"
    default:
      return "Wave 4 — Monitor"
  }
}

export const WAVE_ORDER: Wave[] = [
  "Wave 1 — Immediate (0-6 months)",
  "Wave 2 — Near term (6-18 months)",
  "Wave 3 — Planned (18-36 months)",
  "Wave 4 — Monitor",
]

function actionsFor(asset: CryptoAsset): string[] {
  const actions: string[] = []
  const rec = asset.recommendation

  if (asset.classicallyBroken) {
    actions.push(`Remove ${asset.name} — it is already broken by classical attacks.`)
  }
  actions.push(`Locate every call site (${asset.occurrences} occurrence${asset.occurrences === 1 ? "" : "s"} found in this scan).`)

  if (rec) {
    actions.push(`Introduce ${rec.primary} behind a crypto-abstraction seam so the algorithm is swappable.`)
    if (rec.hybrid) actions.push(`Deploy the hybrid option first: ${rec.hybrid}.`)
    // F8/U6 — the size/latency consequence belongs in the plan, not a footnote.
    if (rec.performanceNote) actions.push(`Budget for the performance change: ${rec.performanceNote}`)
    actions.push(`Validate against ${rec.standard} test vectors and measure size/latency deltas.`)
  } else {
    actions.push("Confirm the primitive and key size, then re-run the scan to pick up a recommendation.")
  }

  if (asset.type === "certificate") {
    actions.push("Reissue through a PQC-capable CA and dual-publish during the overlap window.")
  }
  if (asset.type === "protocol") {
    actions.push("Coordinate the cut-over with external counterparties before disabling the classical suite.")
  }
  if (asset.type === "key") {
    actions.push("Move the key out of the repository into a managed store, then rotate it — assume the current value is compromised.")
  }
  if (asset.type === "hardware-module") {
    actions.push("Confirm the module's PQC firmware roadmap with the vendor; FIPS 203/204 support gates this migration.")
    actions.push("Reference detected from code only — verify the live module inventory out of band.")
  }
  if (asset.type === "cloud-service") {
    actions.push("Check the provider's PQC algorithm catalogue and plan key re-wrapping under a PQC-capable key spec.")
    actions.push("Reference detected from code only — enumerate the actual keys through the provider console or API.")
  }
  if (asset.evidence === "binary") {
    actions.push("Obtain the source for the packaged artifact (or a PQC-capable release) before scheduling the rebuild.")
  }
  if (asset.evidence === "container") {
    actions.push("Rebuild the image from an updated base and redeploy — the running fleet keeps the old crypto until it rolls.")
  }
  actions.push("Re-scan in CI to prove the finding is gone and cannot regress.")
  return actions
}

export function buildRoadmap(assets: CryptoAsset[]): RoadmapItem[] {
  const groups = new Map<string, CryptoAsset[]>()

  for (const asset of assets) {
    // Nothing to migrate for already-PQC or unflagged strong primitives.
    if (asset.family === "PQC") continue
    if (!asset.quantumVulnerable && !asset.classicallyBroken && !asset.recommendation) continue

    const key = `${asset.algorithmId}|${asset.keySize ?? "na"}|${asset.evidence}`
    const bucket = groups.get(key)
    if (bucket) bucket.push(asset)
    else groups.set(key, [asset])
  }

  const items: RoadmapItem[] = []

  for (const [key, group] of groups) {
    const lead = group.reduce((worst, a) => (a.mosca.margin > worst.mosca.margin ? a : worst), group[0])
    const rec = lead.recommendation
    const complexity = rec?.complexity ?? "medium"
    const occurrences = group.reduce((sum, a) => sum + a.occurrences, 0)
    const files = [...new Set(group.map((a) => a.file))]

    const base = BASE_DAYS[lead.evidence] ?? 4
    // Sub-linear scaling: the second file is far cheaper than the first.
    const scale = 1 + Math.log2(files.length + 1) * 0.6
    const effortDays =
      Math.round(
        base *
          scale *
          COMPLEXITY_MULTIPLIER[complexity] *
          CRITICALITY_MULTIPLIER[lead.classification.businessCriticality] *
          10,
      ) / 10

    items.push({
      key,
      title: `Migrate ${lead.name} (${lead.evidence === "dependency" ? "dependency manifest" : lead.evidence} evidence)`,
      wave: waveFor(lead.riskTier, lead.classicallyBroken),
      riskTier: lead.riskTier,
      algorithm: lead.name,
      family: lead.family,
      primitive: lead.primitive,
      target: rec?.primary ?? "Manual review required",
      standard: rec?.standard ?? "—",
      hybrid: rec?.hybrid,
      performanceNote: rec?.performanceNote,
      files,
      assetIds: group.map((a) => a.id),
      occurrences,
      worstMargin: lead.mosca.margin,
      effortDays,
      complexity,
      rationale: lead.mosca.explanation,
      actions: actionsFor(lead),
    })
  }

  const tierRank: Record<RiskTier, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 }
  return items.sort(
    (a, b) => tierRank[a.riskTier] - tierRank[b.riskTier] || b.worstMargin - a.worstMargin || b.occurrences - a.occurrences,
  )
}

export function roadmapTotals(items: RoadmapItem[]) {
  const byWave = new Map<Wave, { items: number; days: number }>()
  for (const wave of WAVE_ORDER) byWave.set(wave, { items: 0, days: 0 })
  for (const item of items) {
    const bucket = byWave.get(item.wave)
    if (!bucket) continue
    bucket.items++
    bucket.days += item.effortDays
  }
  return {
    byWave,
    totalDays: Math.round(items.reduce((s, i) => s + i.effortDays, 0) * 10) / 10,
    totalItems: items.length,
  }
}

export function roadmapToMarkdown(items: RoadmapItem[], label: string): string {
  const totals = roadmapTotals(items)
  const lines: string[] = [
    `# PQC Migration Roadmap — ${label}`,
    "",
    `Generated by ECDAT on ${new Date().toISOString().slice(0, 10)}.`,
    "",
    `**${totals.totalItems}** work items · **${totals.totalDays}** engineer-days`,
    "",
    "> Effort model: base days per evidence type x log-scaled file count x algorithm complexity x business criticality.",
    "> These are planning inputs, not a commercial quote; they estimate engineering effort and migration sequencing.",
    "",
  ]

  for (const wave of WAVE_ORDER) {
    const waveItems = items.filter((i) => i.wave === wave)
    if (!waveItems.length) continue
    const bucket = totals.byWave.get(wave)!
    lines.push(`## ${wave}`, "", `${bucket.items} items · ${Math.round(bucket.days * 10) / 10} engineer-days`, "")
    for (const item of waveItems) {
      lines.push(
        `### ${item.title}`,
        "",
        `- **Risk tier:** ${item.riskTier} (Mosca margin ${item.worstMargin > 0 ? "+" : ""}${item.worstMargin}y)`,
        `- **Target:** ${item.target} — ${item.standard}`,
        ...(item.hybrid ? [`- **Hybrid option:** ${item.hybrid}`] : []),
        ...(item.performanceNote ? [`- **Performance note:** ${item.performanceNote}`] : []),
        `- **Effort:** ${item.effortDays} engineer-days`,
        `- **Files:** ${item.files.slice(0, 8).join(", ")}${item.files.length > 8 ? ` (+${item.files.length - 8} more)` : ""}`,
        "",
        "**Steps**",
        "",
        ...item.actions.map((a, idx) => `${idx + 1}. ${a}`),
        "",
      )
    }
  }

  return lines.join("\n")
}
